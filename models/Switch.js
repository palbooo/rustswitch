// models/Switch.js
const mongoose = require("mongoose");

const SwitchSchema = new mongoose.Schema({
  switchId: {
    type: String,
    required: true,
    unique: true,
  },
  serverId: {
    type: String,
    required: true,
  },
  entityId: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  position: {
    row: {
      type: Number,
      required: true,
    },
    col: {
      type: Number,
      required: true,
    },
  },
  lastState: {
    type: Boolean,
    default: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("Switch", SwitchSchema);
