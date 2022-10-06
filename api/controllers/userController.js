
import bcrypt from 'bcryptjs'
import User from '../models/User.js';
import createError from "./errorController.js";
import jwt from "jsonwebtoken"

/**
 * @access public
 * @route /api/user
 * @method GET
 */
export const getAllUser = async (req, res, next) => {

    
    try {
        const users= await User.find();

        res.status(200).json(users);

    } catch (error) {
        next(error);
        
    }
}

/**
 * @access public
 * @route /api/user/:id
 * @method GET
 */

 export const getSingleUser = async (req, res) => {

    const { id } = req.params;
    try {
        const user = await User.findById(id);
        
        if( !user){
            return next(createError(404, "Single user not found"));
        }

        if(user){
            res.status(200).json(user);
        }
        

    } catch (error) {
        console.log(error);  
    }
}


/**
 * @access public
 * @route /api/student
 * @method POST
 */

 export const createUser= async (req, res) => {

    //make hash pass
    const salt = await bcrypt.genSalt(10);
    const hash_pass = await bcrypt.hash(req.body.password, salt);
    
    try {
        const user = await User.create({...req.body, password: hash_pass});
        res.status(200).json(user)

    } catch (error) {
        console.log(error);  
    }
}

/**
 * @access public
 * @route /api/user/:id
 * @method PUT/PATCH
 */

 export const updateUser = async (req, res) => {
    const { id } = req.params;
    try {
        const user = await User.findByIdAndUpdate(id, req.body, { new : true });
        res.status(200).json(user)

    } catch (error) {
        console.log(error);  
    }
}


/**
 * @access public
 * @route /api/user
 * @method DELETE
 */

 export const deleteUser = async (req, res) => {
    const { id } = req.params;
    try {
        const user = await User.findByIdAndDelete(id);
        res.status(200).json(user);

    } catch (error) {
        console.log(error);  
    }
}

/**
 * @access public
 * @route /api/user/login
 * @method POST
 */

 export const userlogin = async (req, res, next) => {

    // const{ email, password} = req.body;

    try{

        //find user
        const login_user = await User.findOne({ email : req.body.email})

        //check user exists ot not
        if( !login_user ){
            return next(createError(404, "User not found"))
        }

        //check password
        const passwordCheck = await bcrypt.compare(req.body.password, login_user.password );

        //password handle
        if( !passwordCheck){
            return next(createError(404, "Wrong password"))
        }

        //create a token
        const token = jwt.sign({ id : login_user._id, isAdmin : login_user.isAdmin }, process.env.JWT_SECRET );

        //login_user info
        const { password, isAdmin, ...login_info } = login_user._doc;


        res.cookie("access_token", token).status(200).json({
            token : token,
            user : login_info

        });

    }catch(error){
        next(error)
    }
}

/**
 * @access public
 * @route /api/user/register
 * @method POST
 */

 export const userRegister = async (req, res) => {

    //make hash pass
    const salt = await bcrypt.genSalt(10);
    const hash_pass = await bcrypt.hash(req.body.password, salt);
    
    try {
        const user = await User.create({...req.body, password: hash_pass});
        res.status(200).json(user)

    } catch (error) {
        console.log(error);  
    }
}


/**
 * @access public
 * @route /api/me
 * @method GET
 */
export const getLoggedInUser = async ( req, res, next ) => {

    try {

        //get token
        const bearer_token = req.headers.authorization;

        let token = '';

        if( bearer_token ){
            token = bearer_token.split(' ')[1];
            
            //get token user
            const logged_in_user = jwt.verify(token, process.env.JWT_SECRET);

            //user check
            if( !logged_in_user ){
                next(createError(400, 'Invalid token'))
            }

            //user check
            if( logged_in_user ){

                const user = await User.findById(logged_in_user.id);

                res.status(200).json(user);
            }
        }

        //check token exists
        if( !bearer_token  ){
            next(createError(404, 'Token not found'))
        }

    } catch (error) {
        next(error)
        
    }

}