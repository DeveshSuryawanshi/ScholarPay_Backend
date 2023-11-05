const express = require("express");
const { UserModel } = require("../Models/user.model");
const { checkPassword } = require("../Validators/passwordChecker");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BlackListModel } = require("../Models/blacklisting.model");
const SpecialKey = process.env.tokenkey;

const userRouter = express.Router();

userRouter.get("/", async (req, res) => {
  try {
    const users = await UserModel.find();
    res.status(200).json(users);
  } catch (error) {
    res.status(400).json({ error: error });
  }
});

userRouter.post("/register", async(req, res) => {
  try {
    const { name, email, password, phone, college } = req.body;
    const existingUser = await UserModel.find({ email });
    if (existingUser.length) {
      return res
        .status(400)
        .json({ error: "Registration failed User already exists" });
    }
    if (checkPassword(password)) {
        bcrypt.hash(password, 5, async(err, hash) =>{
            const user = new UserModel({name ,email, password : hash, phone, college})
            await user.save();
            return res.status(200).json({"msg" : "The new User has been registered", "registeredUser" : user});
        })
    } else {
      res.status(400).json({
        error:
          "Registration failed ! Password should contain atlese one uppercase, one number and one unique character",
      });
    }
  } catch (error) {
    res.status(400).json({ "error": error });
  }
});


userRouter.post("/login", async(req, res) =>{
    try {
        const {email, password} = req.body;
        const existingUser = await UserModel.findOne({email});
        if(existingUser){
            bcrypt.compare(password, existingUser.password, (err, result) => {
                if(result){
                    const token = jwt.sign({userID : existingUser._id, username : existingUser.name}, SpecialKey, {
                        expiresIn : 420
                    })
                    return res.status(200).json({"msg" : "Login Successfull", "token" : token});
                }else{
                    res.status(400).json({"msg" : "Invalid Credentials! Wrong password provided"});
                }
            })
        }else{
            res.status(400).json({"msg" : "Invalid Credentials! Wrong email provided"});
        }
    } catch (error) {
        res.status(400).json({"error" : error.message});
    }
})

userRouter.post("/logout", async(req, res) =>{
    try {
        const token = req.headers.authorization;
        if(token){
            await BlackListModel.updateMany({}, {$push : {blacklist : [token]}});
            res.status(200).json({msg : "Logout Successfully!"});
        }
    } catch (error) {
        res.status(400).json({error : error});
    }
})


module.exports = {
  userRouter,
};
