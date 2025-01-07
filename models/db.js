// models/db.js
const mongoose = require("mongoose");

// Define the Switch schema
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

const switchLogSchema = new mongoose.Schema({
  switchId: String,
  steamId: String,
  steamName: String, // Steam Username
  avatarUrl: String, // Steam Avatar URL
  state: Boolean,
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

// Initialize the model only if it hasn't been initialized yet
const Switch = mongoose.models.Switch || mongoose.model("Switch", SwitchSchema);
const SwitchLog = mongoose.model("SwitchLog", switchLogSchema);

const connectDB = async () => {
  try {
    await mongoose.connect(
      process.env.MONGODB_URI || "mongodb://localhost:27017/rustplus"
    );
    console.log("MongoDB verbunden");
    return { Switch };
  } catch (error) {
    console.error("MongoDB Verbindungsfehler:", error);
    process.exit(1);
  }
};

module.exports = { connectDB, Switch, SwitchLog };
