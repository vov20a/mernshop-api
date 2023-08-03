const Order = require('../models/Order');
const fs = require('fs');
const fsPromises = fs.promises;
const { v4: uuid } = require('uuid');
const path = require('path');
const User = require('../models/User');

// @desc Get all orders
// @route GET /orders
// @access Private
const getAllOrders = async (req, res) => {
  // Get all orders from MongoDB
  const orders = await Order.find().populate('user').populate('productsInfo.product').lean();
  // If no orders
  if (!orders?.length) {
    return res.status(400).json({ message: 'No orders found' });
  }
  res.json(orders);
};

// @desc Get orders by UserId
// @route GET /orders/userId
// @access Private
const getOrdersByUserId = async (req, res) => {
  //   // Get  orders with userId from MongoDB
  const { userId } = req.params;
  // console.log('userId', userId);
  const orders = await Order.find({ user: userId })
    .populate('user')
    .populate('productsInfo.product')
    .lean();
  // If no orders
  if (!orders?.length) {
    return res.status(400).json({ message: 'No orders by user found' });
  }
  res.json(orders);
};

// @desc Create new order
// @route POST /orders
// @access Private
const createNewOrder = async (req, res) => {
  // console.log(req.body, req.files);
  const { productsInfo, fullName, email, phone, user, totalPrice } = req.body;
  // Confirm data
  if (!productsInfo || !fullName || !email || !phone || !user || !totalPrice) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  // Does the user exist ?
  const findUser = await User.findById(user).exec();

  if (!findUser) {
    return res.status(400).json({ message: 'User not found' });
  }

  //create order
  const orderObject = { productsInfo, fullName, email, phone, user, totalPrice };

  const order = await Order.create(orderObject);
  if (order) {
    //created
    res.status(201).json({ message: `New order ${order._id} of user  ${findUser.email} created` });
  } else {
    res.status(400).json({ message: 'Invalid order data received' });
  }
};

// @desc Update a order
// @route PATCH /orders
// @access Private
const updateOrder = async (req, res) => {
  // console.log(req.body, req.files);
  const { id, productsInfo, fullName, email, phone, user, totalPrice } = req.body;
  // Confirm data
  if (
    !id ||
    !Array.isArray(productsInfo) ||
    !fullName ||
    !email ||
    !phone ||
    !user ||
    !totalPrice
  ) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  // Update order-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }

  // Does the order exist to update?
  const order = await Order.findById(id).exec();
  if (!order) {
    return res.status(400).json({ message: 'Order not found' });
  }
  order.fullName = fullName; // products, fullName, email, phone, user, totalPrice
  order.email = email;
  order.phone = phone;
  order.user = user;
  order.totalPrice = totalPrice;
  order.productsInfo = productsInfo;
  const updatedOrder = await order.save();
  res.json({ message: `Order id ${updatedOrder._id}  updated` });
};

// @desc Delete a order
// @route DELETE /orders
// @access Private
const deleteOrder = async (req, res) => {
  // Delete order-only 'Manager' or 'Admin'
  if (!req.roles.includes('Manager') || !req.roles.includes('Admin')) {
    return res.status(403).json({ message: 'No access' });
  }
  const { id } = req.body;
  // Confirm data
  if (!id) {
    return res.status(400).json({ message: 'Order ID required' });
  }

  // Does the order exist to delete?
  const order = await Order.findById(id).exec();
  if (!order) {
    return res.status(400).json({ message: 'Order not found' });
  }

  const result = await order.deleteOne();
  const reply = `Order ${result._id} with userId ${result.user} deleted`;
  res.json(reply);
};

module.exports = {
  getAllOrders,
  getOrdersByUserId,
  createNewOrder,
  updateOrder,
  deleteOrder,
};
