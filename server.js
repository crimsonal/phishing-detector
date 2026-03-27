import "dotenv/config";
import app from "./app.js";
import analyzeLink from "./controllers/v1/analyze.controller.js";

const PORT = process.env.PORT || 3000;

app.post("/url", analyzeLink)

app.get("/", (req, res) => {
    res.send(".")
})
app.listen(PORT, () => {
  console.log(`Server listening on port http://localhost:${PORT}/`);
});