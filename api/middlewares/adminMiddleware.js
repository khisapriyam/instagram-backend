import createError from "../controllers/errorController.js";
import jwt from 'jsonwebtoken';

//check user is authenticated or not
export const adminMiddleware = (req, res, next) => {

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

        if( !login_user.isAdmin){
            return next(createError(401, "Only admin can access this feature"));
        }
        
        if( login_user){
            req.user = login_user;
            next();
        }

    } catch (error) {
        return next(error);
        
    }

}