const express = require('express');
const router = express.Router();
const categoriesController = require('../controllers/categoriesController');
const verifyJWT = require('../middlewares/verifyJWT');

router.get('/', categoriesController.getAllCategories);

router.use(verifyJWT);

router
  .route('/')
  .post(categoriesController.createNewCategory)
  .patch(categoriesController.updateCategory)
  .delete(categoriesController.deleteCategory);

module.exports = router;
