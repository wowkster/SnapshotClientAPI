import express from "express";
import mysql from "mysql2/promise";
import sha1 from "sha1";
import slowDown from "express-slow-down";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import fs from "fs";
import axios from "axios";

dotenv.config()

const app = express()
const PORT = process.env.PORT || 8080
const usersSpeedLimiter = slowDown({
    windowMs: 10 * 60 * 1000, // 10 minutes
    delayAfter: 200, // allow 200 requests per 10 minutes, then...
    delayMs: 500 // add 500ms of delay per request above 100
})
const keyRateLimit = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 10 // limit each IP to 10 requests per 30m
  });

app.use('/api/users/*', usersSpeedLimiter)
app.use('/api/create-key', keyRateLimit)
app.use(express.json())

// Secure method to ensure only a registered client can access the api
app.use('/api/users/*', async (req, res, next) => {
    const hash = req.headers['sha1-hash-security']
    const clientId = req.headers['client-id']

    if (hash === undefined || clientId === undefined){
        res.status(401).send("The Hash and/or Client Id are missing from this request. Credentials are required to required to verify the request's origin.")
        return
    }

    const clientSecret = await getClientSecret(clientId)

    if (clientSecret === undefined){
        res.status(400).send("Bad Request - Client Id is invalid or does not exist")
        return
    }

    const uriSlug = req.url.split('?')[0]
    const data = req.method + uriSlug + clientSecret + '😎' + process.env.STATIC_SECRET + process.env.CLIENT_SECRET
    const hashedData = sha1(data)

    console.log(hashedData)

    if (hash !== hashedData) {
        // Hash does not match
        res.status(403).send("Invalid Hash was provided. You are forbidden from accessing this resource.")
        return
    }

    next()
})

const con = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    database: "minecraft"
})

setInterval(async () => {
    await con.query("SELECT 1")
}, 2000)

try {
    await con.connect()
    console.log("Connected To Database!")
} catch (err) {
    console.error(err)
}

app.get('/api/users/:uuid/data', async (req, res) => {
    const { uuid } = req.params

    if (!uuidIsValid(uuid)){
        res.status(400).send("Bad Request - UUID is invalid")
        return
    }

    const user = await getRegisteredUser(uuid)

    if (user === undefined) {
        // MySQL threw an error
        res.status(500).send("Internal Database Error - Please notify a developer")
        return
    }

    if (user === null) {
        res.status(404).send("User does not exist")
        return
    }

    const online = user.online.toString('hex') === '01'

    res.status(200).send({
        "uuid" : uuid,
        "userIsRegistered" : (user !== null),
        "cape" : user.cape,
        "online" : online
    })

    fs.writeFile(`capes/${uuid}.png`, Buffer.from(user.cape, 'base64'), (err) => {
        if (err){
            throw err
        }
    })
})

app.patch('/api/users/:uuid/online', async (req, res) => {
    const { uuid } = req.params
    const { online } = req.body

    if (!uuidIsValid(uuid)){
        res.status(400).send("Bad Request - UUID is invalid")
        return
    }

    if(online === undefined){
        res.status(400).send(`Bad Request - Missing "online" property`)
        return
    }

    const user = await getRegisteredUser(uuid)

    if (user === undefined) {
        // MySQL threw an error
        res.status(500).send("Internal Database Error - Please notify a developer")
        return
    }

    if (user === null) {
        res.status(404).send("User does not exist")
        return
    }

    if (!(await setUserOnline(uuid, online))){
        res.status(500).send("Internal Database Error - Please notify a developer")
        return
    }

    res.status(202).send("Updating User Status")
})

app.post('/api/create-key', async (req, res) => {

    if ((await getRegisteredUser(req.body.uuid)) === null) {
        res.status(404).send("UUID is not registered. Please register an Unname Client account first.")
    }

    const clientId = await makeClientId(true)
    const {username} = req.body
    const {password} = req.body

    let authResult:any

    try {
        authResult = await axios.post('https://authserver.mojang.com/authenticate', {
            "agent": {
                "name": "Minecraft",
                "version": 1
            },
            "username": username,
            "password": password,
            "clientToken": clientId,
            "requestUser": true
        })
    } catch (err) {
        res.status(err.response.status).send(err.response.data)
        return
    }

    const uuid = formatUUID(authResult.data.selectedProfile.id)

    const user = await getRegisteredUser(uuid)

    if (user === null) {
        // TODO - Register user if not registered
        res.status(404).send("Must register an Unnamed Client account")
        return
    }

    const secret = makeSecret(clientId)

    if (await userHasClientId(user)){
        const updated = await updateClientId(user, clientId, secret)

        if (!updated){
            res.status(500).send("An Error occured while attemping to create a client ID")
            return
        }
    } else {
        const inserted = await insertNewClientId(user, clientId, secret)

        if (!inserted){
            res.status(500).send("An Error occured while attemping to create a client ID")
            return
        }
    }

    res.status(201).send({
        "uuid" : uuid,
        "clientId" : clientId,
        "clientSecret" : secret
    })
})

app.post('/api/regen-key', (req, res) => {
    res.status(200)
})

app.listen(PORT, () => {
    console.log( `server started at http://localhost:${ PORT }` )
})

function uuidIsValid(uuid: string) : boolean {
    // Check with Validate UUID formatting not against mojang servers
    if (uuid === null || uuid === undefined){
        return false
    }
    return (/^[A-F\d]{8}-[A-F\d]{4}-4[A-F\d]{3}-[89AB][A-F\d]{3}-[A-F\d]{12}$/i).test(uuid)
}

async function setUserOnline(uuid: string, isOnline: boolean) {

    try {
        await con.query(`UPDATE Users SET isOnline=${(isOnline ? '1' : '0')} WHERE uuid='${uuid}';`)
        return true
    } catch (err) {
        console.error(err)
        return false
    }
}

async function getRegisteredUser(uuid: string) {
    // Look up UUID in database and see if any rows exist
    try {
        const [results]:any = await con.query(`SELECT * FROM Users WHERE uuid='${uuid}' LIMIT 1;`)
        if (results.length === 0){
            return null
        }

        const result = results[0]

        return {
            "id" : result.id,
            "uuid" : result.uuid,
            "cape" : result.cape,
            "online" : result.isOnline
        }
    } catch (err) {
        console.error(err)
        return undefined
    }
}

async function makeClientId(checkDB:boolean):Promise<string> {
    const result = [];
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for ( let i = 0; i < 24; i++ ) {
        result.push(characters.charAt(Math.floor(Math.random() * charactersLength)));
    }

    const id = result.join('')

    if (!checkDB){
        return id
    }

    const rows:any = (await con.query(`SELECT * FROM ClientIds WHERE clientIdKey='${id}'`))[0]

    if (rows.length > 0){
        return await makeClientId(true)
    }

    return id;
}

async function userHasClientId(user:{ id: number; uuid: string; cape: string; online: boolean; }): Promise<boolean> {
    try {
        const [results]:any = await con.query(`select * from ClientIds where userId=${user.id};`)
        return results.length !== 0
    } catch (err) {
        throw err
    }
}

async function insertNewClientId(user: { id: number; uuid: string; cape: string; online: boolean; }, clientId: string, secret: string) {
    try {
        await con.query(`INSERT INTO ClientIds (userId, clientIdKey, clientSecret) VALUES (${user.id}, '${clientId}', '${secret}');`)
        return true
    } catch (err) {
        console.error(err)
        return false
    }
}

function makeSecret(clientId:string){
    return sha1(clientId + (new Date()).getTime() + makeClientId(false))
}

function formatUUID(uuid:string) {
    return uuid.replace(/(\w{8})(\w{4})(\w{4})(\w{4})(\w{12})/, "$1-$2-$3-$4-$5")
}

async function getClientSecret(clientId: string | import("qs").ParsedQs | string[] | import("qs").ParsedQs[]) {
    try {
        const rows:any = (await con.query(`SELECT clientSecret FROM ClientIds WHERE clientIdKey='${clientId}' LIMIT 1;`))[0]
        return rows[0]?.clientSecret
    } catch (err) {
        return null
    }
}

async function updateClientId(user: { id: number; uuid: string; cape: string; online: boolean; }, clientId: string, secret: string) : Promise<boolean> {
    try {
        await con.query(`UPDATE ClientIds SET clientIdKey='${clientId}', clientSecret='${secret}' WHERE userID=${user.id};`)
        return true
    } catch (err) {
        console.error(err)
        return false
    }
}

