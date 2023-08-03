const { Schema, model } = require('mongoose');

const ProductSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },

    price: {
      type: Number,
      defaul: 0,
      required: true,
    },
    rating: {
      type: Number,
      default: 0,
      required: true,
    },
    category: {
      type: Schema.Types.ObjectId,
      ref: 'Category',
      required: true,
    },
    //   sizes: {
    //     type: Array,
    //     default: [],
    //   },
    //   colors: {
    //     type: Array,
    //     default: [],
    //   },
    productImg: String,
  },
  {
    timestamps: true,
  },
);

module.exports = model('Product', ProductSchema);
