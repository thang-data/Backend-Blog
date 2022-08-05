"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.io = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const morgan_1 = __importDefault(require("morgan"));
const index_1 = __importDefault(require("./routes/index"));
const http_1 = require("http");
const socket_io_1 = require("socket.io");
const path_1 = __importDefault(require("path"));
// Middleware
const app = express_1.default();
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: false }));
app.use(cors_1.default());
app.use(morgan_1.default('dev'));
app.use(cookie_parser_1.default());
// Socket.io
const http = http_1.createServer(app);
exports.io = new socket_io_1.Server(http);
const socket_1 = require("./config/socket");
exports.io.on("connection", (socket) => {
    socket_1.SocketServer(socket);
});
// Routes
app.use('/api', index_1.default);
// Database
require("./config/database");
// Production Deploy
if (process.env.NODE_ENV === 'production') {
    app.use(express_1.default.static('client/build'));
    app.get('*', (req, res) => {
        res.sendFile(path_1.default.join(__dirname, '../client', 'build', 'index.html'));
    });
}
// server listenning
const PORT = process.env.PORT || 5000;
http.listen(PORT, () => {
    console.log('Server is running on port', PORT);
});
