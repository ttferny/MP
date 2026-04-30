const express = require("express"); // [1] Import Express; used by [4].
const cors = require("cors"); // [2] Import CORS middleware; used by [5].

const analyzeRoute = require("./routes/analyze"); // [3] Import route module; mounted by [7].

const app = express(); // [4] Create app instance from [1].
app.use(cors()); // [5] Enable CORS using [2].
app.use(express.json()); // [6] Enable JSON parsing for [7].

app.use("/analyze", analyzeRoute); // [7] Mount [3] under /analyze using [6].

const PORT = 3000; // [8] Define port used by [9].
app.listen(PORT, () => { // [9] Start server on [8].
  console.log(`Server running on http://localhost:${PORT}`); // [10] Log URL using [8].
});