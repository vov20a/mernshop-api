const { Schema, model } = require('mongoose');

const subSchema = new Schema({
  // _id: Schema.Types.ObjectId,
  product: {
    type: Schema.Types.ObjectId,
    ref: 'Product',
    required: true,
  },
  count: {
    type: Number,
    required: true,
  },
});

const OrderSchema = new Schema(
  {
    // products: {
    //   type: Array,
    //   required: true,
    // },
    productsInfo: [subSchema],
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    phone: {
      type: String,
      required: true,
    },
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    totalPrice: Number,
  },
  {
    timestamps: true,
  },
);

module.exports = model('Order', OrderSchema);
