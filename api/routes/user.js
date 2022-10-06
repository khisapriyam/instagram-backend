import express from 'express';
import { createUser, deleteUser, getAllUser, getSingleUser, updateUser, userlogin, userRegister, getLoggedInUser } from '../controllers/userController.js';
import { adminMiddleware } from '../middlewares/adminMiddleware.js';
import { authMiddleware } from '../middlewares/authMiddleware.js';
import { userMiddleware } from '../middlewares/userMiddleware.js';


//init router
const router = express.Router();

//user Auth Route
router.post('/login', userlogin);
router.post('/register', userRegister);
router.get('/me', getLoggedInUser);


//route REST API
router.route('/').get(adminMiddleware, getAllUser).post(adminMiddleware, createUser);
router.route('/:id').get(userMiddleware, getSingleUser).delete(userMiddleware, deleteUser).put(userMiddleware, updateUser).patch(userMiddleware, updateUser);


//export default router
export default router;