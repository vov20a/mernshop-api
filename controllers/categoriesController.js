const Category = require('../models/Category');
const Product = require('../models/Product');

// @desc Get all categories
// @route GET /categories
// @access Public
const getAllCategories = async (req, res) => {
  // Get all categories from MongoDB
  const cats = await Category.find().populate('parentCategory').lean();

  // If no categories
  if (!cats?.length) {
    return res.status(400).json({ message: 'No categories found' });
  }

  res.json(cats);
};

// @desc Create new category
// @route POST /categories
//@if category-parent, parentCategory=0,else parentCategory= categoryId of parent cat
// @access Private
const createNewCategory = async (req, res) => {
  // Create and store new product-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }

  const { title, parentCategory } = req.body;
  // Confirm data
  if (!title) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Check for duplicate category
  const duplicate = await Category.findOne({ title })
    .collation({ locale: 'en', strength: 2 })
    .lean()
    .exec();

  if (duplicate) {
    return res.status(409).json({ message: 'Duplicate category' });
  }
  const category = await Category.create({ title, parentCategory });
  if (category) {
    //created
    res
      .status(201)
      .json({ message: `New category ${title} of categoryId ${category._id} created` });
  } else {
    res.status(400).json({ message: 'Invalid category data received' });
  }
};

// @desc Update a category
// @route PATCH /categories
// @access Private
const updateCategory = async (req, res) => {
  // Update product-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }

  const { id, title, parentCategory } = req.body;
  // console.log(parentCategory);
  let parent;
  parentCategory === '0' ? (parent = null) : (parent = parentCategory);
  // console.log(parent);

  // Confirm data
  if (!id || !title || !parentCategory) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Does the category exist to update?
  const category = await Category.findById(id).exec();

  if (!category) {
    return res.status(400).json({ message: 'Category not found' });
  }

  // Check for duplicate title
  const duplicate = await Category.findOne({ title })
    .collation({ locale: 'en', strength: 2 })
    .lean()
    .exec();

  // Allow updates to the original category
  if (duplicate && duplicate?._id.toString() !== id) {
    return res.status(409).json({ message: 'Duplicate title' });
  }

  category.title = title;
  category.parentCategory = parent;

  const updatedCategory = await category.save();

  res.json({ message: `${updatedCategory.title}  updated` });
};

// @desc Delete a category
// @route DELETE /categories
// @access Private
const deleteCategory = async (req, res) => {
  // Delete product-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }

  const { id } = req.body;
  // Confirm data
  if (!id) {
    return res.status(400).json({ message: 'Product ID Required' });
  }

  // Does the category exist to delete?
  const category = await Category.findById(id).exec();

  if (!category) {
    return res.status(400).json({ message: 'Category not found' });
  }
  // Does the cat  have children cats?
  const childCategory = await Category.findOne({ parentCategory: id }).lean().exec();
  if (childCategory) {
    return res.status(400).json({ message: 'Category has child category' });
  }

  // Does the category still have assigned products?
  const product = await Product.findOne({ category: id }).lean().exec();
  if (product) {
    return res.status(400).json({ message: 'Category has assigned products' });
  }

  const result = await category.deleteOne();

  const reply = `Category ${result.title} deleted`;

  res.json(reply);
};

module.exports = {
  getAllCategories,
  createNewCategory,
  updateCategory,
  deleteCategory,
};
