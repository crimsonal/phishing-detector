import app from "./app.js";
import express from "express"
import analyzeLink from "./controllers/v1/analyze.controller.js";
const PORT = process.env.PORT || 3000

const router = express.Router();

app.post("/url", analyzeLink)

app.get("/", (req, res) => {
    res.send(".")
})
app.listen(PORT, () => {
  console.log(`Server listening on port http://localhost:${PORT}/`);
});