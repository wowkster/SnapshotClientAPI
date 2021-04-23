import express from "express";
import mysql from "mysql2/promise";
import sha1 from "sha1";
import slowDown from "express-slow-down";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import fs from "fs";
import axios from "axios";
import bcrypt from "bcrypt";
dotenv.config();
const app = express();
const PORT = process.env.PORT || 8080;
const usersSpeedLimiter = slowDown({
    windowMs: 10 * 60 * 1000,
    delayAfter: 200,
    delayMs: 500 // add 500ms of delay per request above 100
});
const keyRateLimit = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 10 // limit each IP to 10 requests per 30m
});
app.use('/api/users/*', usersSpeedLimiter);
app.use('/api/create-key', keyRateLimit);
app.use('/api/register', keyRateLimit);
app.use(express.json());
// Secure method to ensure only a registered client can access the api
app.use('/api/users/*', async (req, res, next) => {
    const hash = req.headers['sha1-hash-security'];
    const clientId = req.headers['client-id'];
    if (hash === undefined || clientId === undefined) {
        res.status(401).send("The Hash and/or Client Id are missing from this request. Credentials are required to required to verify the request's origin.");
        return;
    }
    const clientSecret = await getClientSecret(clientId);
    if (clientSecret === undefined) {
        res.status(400).send({
            message: "CLIENT_ID_INVALID",
            errors: ["Client ID is invalid or does not exist."]
        });
        return;
    }
    const uriSlug = req.url.split('?')[0];
    const data = req.method + uriSlug + clientSecret + '😎' + process.env.STATIC_SECRET + process.env.CLIENT_SECRET;
    const hashedData = sha1(data);
    console.log(hashedData);
    if (hash !== hashedData) {
        // Hash does not match
        res.status(403).send("Invalid Hash was provided. You are forbidden from accessing this resource.");
        return;
    }
    next();
});
const con = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    database: "minecraft"
});
setInterval(async () => {
    await con.query("SELECT 1");
}, 2000);
try {
    await con.connect();
    console.log("Connected To Database!");
}
catch (err) {
    console.error(err);
}
app.get('/api/users/:uuid/data', async (req, res) => {
    const { uuid } = req.params;
    if (!uuidIsValid(uuid)) {
        res.status(400).send({
            message: "UUID_INVALID",
            errors: ["UUID is not compliant with standard UUID v4 formatting. Dashes are expcted."]
        });
        return;
    }
    const user = await getRegisteredUserFromUUID(uuid);
    if (user === undefined) {
        // MySQL threw an error
        res.status(500).send("Internal Database Error - Please notify a developer");
        return;
    }
    if (user === null) {
        res.status(404).send("User does not exist");
        return;
    }
    const online = user.online.toString('hex') === '01';
    res.status(200).send({
        "uuid": uuid,
        "userIsRegistered": (user !== null),
        "cape": user.cape,
        "online": online
    });
    fs.writeFile(`capes/${uuid}.png`, Buffer.from(user.cape, 'base64'), (err) => {
        if (err) {
            throw err;
        }
    });
});
app.patch('/api/users/:uuid/online', async (req, res) => {
    const { uuid } = req.params;
    const { online } = req.body;
    if (!uuidIsValid(uuid)) {
        res.status(400).send({
            message: "UUID_INVALID",
            errors: ["UUID is not compliant with standard UUID v4 formatting. Dashes are expcted."]
        });
        return;
    }
    if (online === undefined) {
        res.status(400).send({
            message: "ONILNE_UNDEFINED",
            errors: ["Request must contain an \"online\" atribute."]
        });
        return;
    }
    const user = await getRegisteredUserFromUUID(uuid);
    if (user === undefined) {
        // MySQL threw an error
        res.status(500).send("Internal Database Error - Please notify a developer");
        return;
    }
    if (user === null) {
        res.status(404).send("User does not exist");
        return;
    }
    if (!(await setUserOnline(uuid, online))) {
        res.status(500).send("Internal Database Error - Please notify a developer");
        return;
    }
    res.status(202).send("Updating User Status");
});
app.post('/api/create-key', async (req, res) => {
    const uuidBody = req.body.uuid;
    if (!uuidIsValid(uuidBody)) {
        res.status(400).send({
            message: "UUID_INVALID",
            errors: ["UUID is not compliant with standard UUID v4 formatting. Dashes are expcted."]
        });
        return;
    }
    if ((await getRegisteredUserFromUUID(uuidBody)) === null) {
        res.status(404).send("UUID is not registered. Please register an Unnamed Client account first.");
    }
    const clientId = await makeClientId(true);
    const { username } = req.body;
    const { password } = req.body;
    let authResult;
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
        });
    }
    catch (err) {
        res.status(err.response.status).send(err.response.data);
        return;
    }
    const uuid = formatUUID(authResult.data.selectedProfile.id);
    const user = await getRegisteredUserFromUUID(uuid);
    if (user === null) {
        // TODO - Register user if not registered
        res.status(404).send("Must register an Unnamed Client account");
        return;
    }
    const secret = makeSecret(clientId);
    if (await userHasClientId(user)) {
        const updated = await updateClientId(user, clientId, secret);
        if (!updated) {
            res.status(500).send("An Error occured while attemping to create a client ID");
            return;
        }
    }
    else {
        const inserted = await insertNewClientId(user, clientId, secret);
        if (!inserted) {
            res.status(500).send("An Error occured while attemping to create a client ID");
            return;
        }
    }
    res.status(201).send({
        "uuid": uuid,
        "clientId": clientId,
        "clientSecret": secret
    });
});
app.post('/api/register', async (req, res) => {
    const { username } = req.body;
    const { email } = req.body;
    const { password } = req.body;
    const { passwordRepeated } = req.body;
    const { uuid } = req.body;
    const validated = validateInput({ username, email, password, passwordRepeated, uuid });
    if (!validated.valid) {
        res.status(400).send({
            message: "INPUT_INVALID",
            errors: validated.errors
        });
        return;
    }
    const uuidUser = await getRegisteredUserFromUUID(uuid);
    if (uuidUser !== null) {
        res.status(400).send({
            message: "UUID_TAKEN",
            errors: ["UUID is already being used"]
        });
        return;
    }
    const emailUser = await getRegisteredUserFromEmail(email);
    if (emailUser !== null) {
        res.status(400).send({
            message: "EMAIL_TAKEN",
            errors: ["Email is already being used"]
        });
        return;
    }
    const usernameUser = await getRegisteredUserFromUsername(username);
    if (usernameUser !== null) {
        res.status(400).send({
            message: "USERNAME_TAKEN",
            errors: ["Username is already being used"]
        });
        return;
    }
    if (!await registerNewUser({ uuid, email, username, password })) {
        res.status(500).send({
            message: "MYSQL_ERROR",
            errors: ["An Error Occured while trying to register your account"]
        });
        return;
    }
    res.status(201).send("Registered User");
});
app.listen(PORT, () => {
    console.log(`server started at http://localhost:${PORT}`);
});
// PULL USERS FROM DATABASE - ===============================================
async function getRegisteredUserFromField(field, value) {
    try {
        const [results] = await con.query(`SELECT * FROM Users WHERE ${field}='${value}' LIMIT 1;`);
        if (results.length === 0) {
            return null;
        }
        const result = results[0];
        return {
            "id": result.id,
            "uuid": result.uuid,
            "cape": result.cape,
            "online": result.isOnline,
            "email": result.email,
            "username": result.username
        };
    }
    catch (err) {
        console.error(err);
        return undefined;
    }
}
async function getRegisteredUserFromUUID(uuid) {
    // Look up UUID in database and see if any rows exist
    return await getRegisteredUserFromField('uuid', uuid);
}
async function getRegisteredUserFromEmail(email) {
    // Look up Email in database and see if any rows exist
    return await getRegisteredUserFromField('email', email);
}
async function getRegisteredUserFromUsername(username) {
    // Look up Username in database and see if any rows exist
    return await getRegisteredUserFromField('username', username);
}
// USER REGISTRATION - ===============================================
async function registerNewUser(newUser) {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newUser.password, salt);
        await con.query(`INSERT INTO Users (uuid, email, username, password) VALUES ('${newUser.uuid}', '${newUser.email}', '${newUser.username}', '${hashedPassword}');`);
        return true;
    }
    catch (err) {
        console.error(err);
        return false;
    }
}
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    return hash;
}
// USER LOGIN - ===============================================
async function loginIsValid(loginAttempt) {
    return true;
}
// USER MODIFICATION - ===============================================
async function setUserOnline(uuid, isOnline) {
    try {
        await con.query(`UPDATE Users SET isOnline=${(isOnline ? '1' : '0')} WHERE uuid='${uuid}';`);
        return true;
    }
    catch (err) {
        console.error(err);
        return false;
    }
}
// CLIENT SECRETS - ===============================================
async function makeClientId(checkDB) {
    const result = [];
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < 24; i++) {
        result.push(characters.charAt(Math.floor(Math.random() * charactersLength)));
    }
    const id = result.join('');
    if (!checkDB) {
        return id;
    }
    const rows = (await con.query(`SELECT * FROM ClientIds WHERE clientIdKey='${id}'`))[0];
    if (rows.length > 0) {
        return await makeClientId(true);
    }
    return id;
}
async function userHasClientId(user) {
    try {
        const [results] = await con.query(`select * from ClientIds where userId=${user.id};`);
        return results.length !== 0;
    }
    catch (err) {
        throw err;
    }
}
function makeSecret(clientId) {
    return sha1(clientId + (new Date()).getTime() + makeClientId(false));
}
async function insertNewClientId(user, clientId, secret) {
    try {
        await con.query(`INSERT INTO ClientIds (userId, clientIdKey, clientSecret) VALUES (${user.id}, '${clientId}', '${secret}');`);
        return true;
    }
    catch (err) {
        console.error(err);
        return false;
    }
}
async function getClientSecret(clientId) {
    var _a;
    try {
        const rows = (await con.query(`SELECT clientSecret FROM ClientIds WHERE clientIdKey='${clientId}' LIMIT 1;`))[0];
        return (_a = rows[0]) === null || _a === void 0 ? void 0 : _a.clientSecret;
    }
    catch (err) {
        return null;
    }
}
async function updateClientId(user, clientId, secret) {
    try {
        await con.query(`UPDATE ClientIds SET clientIdKey='${clientId}', clientSecret='${secret}' WHERE userID=${user.id};`);
        return true;
    }
    catch (err) {
        console.error(err);
        return false;
    }
}
// INPUT VALIDATION - ===============================================
function formatUUID(uuid) {
    return uuid.replace(/(\w{8})(\w{4})(\w{4})(\w{4})(\w{12})/, "$1-$2-$3-$4-$5");
}
function uuidIsValid(uuid) {
    // Check with Validate UUID formatting not against mojang servers
    if (uuid === null || uuid === undefined) {
        return false;
    }
    return (/^[A-F\d]{8}-[A-F\d]{4}-4[A-F\d]{3}-[89AB][A-F\d]{3}-[A-F\d]{12}$/i).test(uuid);
}
function passwordIsValid(password) {
    return (/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/).test(password);
}
function usernameIsValid(username) {
    return (/^[a-zA-Z0-9_]{3,24}$/).test(username);
}
function emailIsValid(email) {
    return (/(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/).test(email);
}
function validateInput(input) {
    const userInput = {
        "valid": true,
        "errors": []
    };
    if (!usernameIsValid(input.username)) {
        userInput.errors.push("Username is invalid. Must only contain alphanumeric characters and underscores.");
    }
    if (!emailIsValid(input.email)) {
        userInput.errors.push("Email is invalid.");
    }
    if (!passwordIsValid(input.password)) {
        userInput.errors.push("Password is invalid. Must be at least 8 characters and contain at least one uppercase letter, one lowercase letter and one number.");
    }
    if (!passwordIsValid(input.passwordRepeated)) {
        userInput.errors.push("Repeated Password is invalid. Must be at least 8 characters and contain at least one uppercase letter, one lowercase letter and one number.");
    }
    if (!uuidIsValid(input.uuid)) {
        userInput.errors.push("UUID is not compliant with standard UUID v4 formatting. Dashes are expcted.");
    }
    if (!(input.password === input.passwordRepeated)) {
        userInput.errors.push("Passwords do not match.");
    }
    if (userInput.errors.length > 0) {
        userInput.valid = false;
    }
    return userInput;
}
//# sourceMappingURL=index.js.map