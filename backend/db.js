const mongoose = require('mongoose');
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, ".env") });


// URL for using Mongo db Atlas
const mongoURI=process.env.MONGO_URI;

// connecting to monogodb
const connectToMongo = ()=>{
    mongoose.connect(mongoURI, ()=>{
        console.log("connnected to mongo successfully!");
    })
}

module.exports = connectToMongo;