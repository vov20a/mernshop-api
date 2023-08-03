const Product = require('../models/Product');
const fs = require('fs');
const fsPromises = fs.promises;
const { v4: uuid } = require('uuid');
const path = require('path');

// @desc Get all products count
// @route GET /products/count
// @access Public
const getCount = async (req, res) => {
  let count = 0;
  const categoryId = req.query?.categoryId;

  const search = req.query?.query;
  const input = search ? { title: new RegExp(search, 'i') } : {};

  if (categoryId) {
    count = await Product.find({
      $and: [
        { category: categoryId },
        // , input
      ],
    })
      .countDocuments()
      .lean();
  } else {
    count = await Product.find(input).countDocuments().lean();
  }

  // const count = await Product.countDocuments().lean();
  // if (!count) {
  //   return res.status(400).json({ message: 'No productsCount ' });
  // }
  res.json(count);
};

// @desc Get all products
// @route GET /products
// @access Public
const getAllProducts = async (req, res) => {
  const startProduct = req.query?.startProduct ?? undefined;
  const limit = req.query?.limit ?? undefined;
  let sort = req.query?.sort;
  sort = sort ? `{"${sort}": 1 }` : '{"rating":1}';

  const search = req.query?.search;
  const input = search ? { title: new RegExp(search, 'i') } : {};
  // console.log(req.query);
  // Get all products from MongoDB
  const products = await Product.find(input)
    .sort(JSON.parse(sort))
    .skip(startProduct)
    .limit(limit)
    .populate('category')
    .lean();
  //

  // If no products
  if (!products?.length) {
    return res.status(400).json({ message: 'No products found' });
  }

  // res.json({ products, count });
  res.json(products);
};

// @desc Get products by categoryId
// @route GET /products/:categoryId
// @access Public
const getProductsByCategoryId = async (req, res) => {
  const startProduct = req.query?.startProduct;
  const limit = req.query?.limit;
  let sort = req.query?.sort;
  sort = sort ? `{"${sort}": 1 }` : '{"rating":1}';

  const { categoryId } = req.params;

  const products = await Product.find({ category: categoryId })
    .sort(JSON.parse(sort))
    .skip(startProduct)
    .limit(limit)
    .populate('category')
    .lean();

  // If no products
  if (!products?.length) {
    return res.status(400).json({ message: 'No products found' });
  }

  res.json(products);
};

// @desc Create new product
// @route POST /products
// @access Private
const createNewProduct = async (req, res) => {
  // console.log(req.body, req.files);
  const { title, description, price, rating, category } = req.body;
  // Confirm data
  if (!title || !description || !price || !rating || !category) {
    return res.status(400).json({ message: 'All fields except productImg are required' });
  }

  // Check for duplicate product
  const duplicate = await Product.findOne({ title })
    .collation({ locale: 'en', strength: 2 })
    .lean()
    .exec();

  if (duplicate) {
    return res.status(409).json({ message: 'Duplicate product' });
  }

  // Create and store new product-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }

  //create folder uploads and load file
  // console.log('file', req.files);
  let fileName = '';
  if (req.files) {
    fileName = uuid() + '_' + req.files.productImg.name;
    // req.files.productImg.mv(path.join(__dirname, '..', 'uploads', fileName));
    if (!fs.existsSync(path.join(__dirname, '..', 'public', 'uploads'))) {
      await fsPromises.mkdir(path.join(__dirname, '..', 'public', 'uploads'));
    }
    await fsPromises.appendFile(
      path.join(__dirname, '..', 'public', 'uploads', fileName),
      req.files.productImg.data,
    );
  }

  const productObject = fileName
    ? { title, description, price, rating, category, productImg: fileName }
    : { title, description, price, rating, category };

  const product = await Product.create(productObject);
  if (product) {
    //created
    res.status(201).json({ message: `New product ${title} of category   ${category} created` });
  } else {
    res.status(400).json({ message: 'Invalid product data received' });
  }
};

// @desc Update a product
// @route PATCH /products
// @access Private
const updateProduct = async (req, res) => {
  // console.log(req.body, req.files);
  const { id, title, description, price, rating, category, productImg } = req.body;

  // Confirm data
  if (!id || !title || !description || !price || !rating || !category) {
    return res.status(400).json({ message: 'All fields except productImg are required' });
  }

  // Does the user exist to update?
  const product = await Product.findById(id).exec();

  if (!product) {
    return res.status(400).json({ message: 'Product not found' });
  }

  // Check for duplicate title
  const duplicate = await Product.findOne({ title })
    .collation({ locale: 'en', strength: 2 })
    .lean()
    .exec();

  // Allow updates to the original product
  if (duplicate && duplicate?._id.toString() !== id) {
    return res.status(409).json({ message: 'Duplicate title' });
  }

  // Update product-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }

  // load file.if productImg(json file) exists-take it,else exists req.files(form-data) and take itand delete old
  let fileName = '';
  if (req.files) {
    // console.log(req.files.productImg);
    fileName = uuid() + '_' + req.files.productImg.name;
    await fsPromises.appendFile(
      path.join(__dirname, '..', 'public', 'uploads', fileName),
      req.files.productImg.data,
    );
    if (product.productImg) {
      await fsPromises.unlink(path.join(__dirname, '..', 'public', 'uploads', product.productImg));
    }
  }

  product.title = title;
  product.description = description;
  product.price = price;
  product.rating = rating;
  product.category = category;
  product.productImg = fileName !== '' ? fileName : productImg;

  const updatedProduct = await product.save();

  res.json({ message: `${updatedProduct.title} of category ${updatedProduct.category}  updated` });
};

// @desc Delete a product
// @route DELETE /products
// @access Private
const deleteProduct = async (req, res) => {
  // Delete product-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }

  const { id } = req.body;

  // Confirm data
  if (!id) {
    return res.status(400).json({ message: 'Product ID Required' });
  }

  // Does the user still have assigned notes?
  //   const note = await Note.findOne({ user: id }).lean().exec();
  //   if (note) {
  //     return res.status(400).json({ message: 'User has assigned notes' });
  //   }

  // Does the user exist to delete?
  const product = await Product.findById(id).exec();

  if (!product) {
    return res.status(400).json({ message: 'Product not found' });
  }

  if (product.productImg) {
    await fsPromises.unlink(path.join(__dirname, '..', 'public', 'uploads', product.productImg));
  }

  const result = await product.deleteOne();

  const reply = `Product ${result.title} with ID ${result._id} deleted`;

  res.json(reply);
};

module.exports = {
  getCount,
  getAllProducts,
  getProductsByCategoryId,
  createNewProduct,
  updateProduct,
  deleteProduct,
};
