const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const server = express();
server.use(express.json());

const saltRounds = 10;

const getDataStore = () => {
    const store = {};

    const authenticateUser = async ({name, password }) => {
        // TODO add safety checks
        if(store[name]){ 
            const match = await bcrypt.compare(password, store[name].password);
            
            if(match){
                const token = jwt.sign(
                    { user_id: name },
                    "randomCharForTokenKey",
                    {
                      expiresIn: "2h",
                    }
                  );
                return {
                    error: false,
                    token
                }
            }
            return {
                error: true
            }
        }
        return {
            error: true
        }
    }

    const addUser = async ({name, password}) => {
        // TODO add safety checks
        if(store[name]){
            return {
                error: true
            }
        }
        const salt = await bcrypt.genSalt(saltRounds);
        const hash = await bcrypt.hash(password, salt);
        if(hash){
            store[name] = {
                name,
                password: hash
            }

            return {
                error: false
            }
        }

        return {
            error: true
        }
        
    }

    return {
        authenticateUser,
        addUser
    }

}

const dataStore = getDataStore();


server.post("/register", async (req, res) => {
    const { name, password } = req.body;
    const result = await dataStore.addUser({ name, password });
    if(!result.error){
        res.status(200).send(`${name} has been registered`);
    }else{
        res.status(400).send(`There was an issue registering user ${name}`);
    }
});

server.post("/login", async (req, res) => {
    const { name, password } = req.body;
    const result = await dataStore.authenticateUser({ name, password });
    if(!result.error){
        res.status(200).send(`${name} is authenticated. JWT token is ${result.token}`);
    }else{
        res.status(400).send(`There was an issue authenticating user ${name}`);
    }
});

server.listen(3000, () => {
    console.log(`Server running on port 3000`);
});
