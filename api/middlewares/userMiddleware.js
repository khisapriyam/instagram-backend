import createError from "../controllers/errorController.js";
import jwt from 'jsonwebtoken';

//check user is authenticated or not
export const userMiddleware = (req, res, next) => {

    const token = req.cookies.access_token;

    //check token
    try {
        if( !token ){
            return next(createError(401, "you are not authenticated"));
        }

        //if user is logged in
        const login_user = jwt.verify(token, process.env.JWT_SECRET);

        if( !login_user ){
            return next(createError(401, "invalid token"));
        }

        if( login_user.id !== req.params.id ){
            return next(createError(401, "You are not allowed to access this feature"));
        }
        
        if( login_user){
            req.user = login_user;
            next();
        }

    } catch (error) {
        return next(error);
        
    }

}