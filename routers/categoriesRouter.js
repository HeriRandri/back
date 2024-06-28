const { Router } = require("express");
const arctilesData = require("../controllers/categoriesController");

const routeArt = Router();

routeArt.get("/topStories", arctilesData.topStories_get);
routeArt.get("/tech", arctilesData.technology_get);
routeArt.get("/science", arctilesData.science_get);
routeArt.get("/sport", arctilesData.sport_get);
routeArt.get("/heath", arctilesData.heath_get);
routeArt.get("/world", arctilesData.world_get);
