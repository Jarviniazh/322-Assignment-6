require('dotenv').config();
const bcrypt = require('bcryptjs');

const mongoose = require('mongoose');
let Schema = mongoose.Schema;


let userSchema = new Schema({
  userName: {
    type: String,
    unique: true},
  password: String,
  email: String,
  loginHistory: [{
    dateTime: Date,
    userAgent: String,
  }],
  
});

let User; // to be defined on new connection (see initialize)

function initialize() {
    return new Promise(function (resolve, reject) {
        let db = mongoose.createConnection(process.env.MONGODB);
        db.on('error', (err)=>{
            reject(err); // reject the promise with the provided error
        });
        db.once('open', ()=>{
            User = db.model("users", userSchema);
            resolve();
        });
    });
}

function registerUser(userData) {
    return new Promise((resolve, reject) => {
        if (userData.password == userData.password2) {
            bcrypt.hash(userData.password, 10)
                .then(hash => {
                    userData.password = hash;
                    let newUser = new User(userData);
                    newUser.save().then(() => {
                        resolve();
                    }).catch(err => {
                        if(err.code == 11000){
                            reject("User Name already taken");
                        } else {
                            reject("There was an error creating the user: " + err);
                        }
                    })
                }).catch(err => {
                    console.log("Error during password hashing:", err);
                    reject("There was an error encrypting the password");
                }) 
        } else {
            reject("Invalid password");
        }
    });
}

function checkUser(userData) {
    return new Promise((resolve, reject) => {
        User.find({userName: userData.userName})
            .exec()
            .then((users) => {
                if(users.length == 0){
                    reject("User Name " + userData.userName + " not found");
                } else {
                    bcrypt.compare(userData.password, users[0].password)
                        .then((res) => {
                            if(res){
                                if(users[0].loginHistory.length == 8){
                                    users[0].loginHistory.pop();
                                }
                                users[0].loginHistory.unshift({dateTime: (new Date()).toString(), userAgent: userData.userAgent});


                                User.updateOne({userName: users[0].userName}, {
                                    $set: {loginHistory: users[0].loginHistory}
                                }).exec()
                                .then(() => {
                                    resolve(users[0]);
                                }).catch(err => {
                                    reject("Unable to verify the user: " + err);
                                });
                            } else {
                                reject("Incorrect Password for user: " + userData.userName);
                            }
                        });
                }
            }).catch(err => {
                reject("Error finding user: " + userData.userName);
            });
    });            
}

module.exports = {
    initialize,
    registerUser,
    checkUser };