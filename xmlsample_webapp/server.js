import express from "express";
import bodyParser from "body-parser";
import { getUserDetails, save_dtd_value, getDTDdetails, getExternalPublicDTDdetails, getExternalDTDdetails } from "./controller.js";

const app = express();

// serve frontend files
app.use(express.static("public"));

// read XML as plain text
app.use(bodyParser.text({ type: "application/xml" }));

// route
app.post("/api/user", getUserDetails);
app.post("/api/dtd",getDTDdetails);
app.post("/api/external_dtd",getExternalDTDdetails);
app.post("/api/public_external_dtd",getExternalPublicDTDdetails);
app.post("/api/save_dtd_value",save_dtd_value);
// start server
app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
});
