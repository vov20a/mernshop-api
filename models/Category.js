const { Schema, model } = require('mongoose');

const CategorySchema = new Schema(
  {
    title: {
      type: String,
      required: true,
      unique: true,
    },
    parentCategory: {
      type: Schema.Types.ObjectId,
      ref: 'Category',
      required: false,
    },
  },
  {
    timestamps: true,
  },
);

module.exports = model('Category', CategorySchema);
