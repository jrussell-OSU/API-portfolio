
//Author: Jacob Russell
//API Portfolio Project
//OSU: CS493
//05-19-22


//-------------------SETUP--------------------------


'use strict';

const express = require('express');
const app = express();

app.enable('trust proxy');

const {Datastore} = require('@google-cloud/datastore');
const { auth } = require('express-openid-connect');
const { engine } = require('express-handlebars');
const config = require('./secrets/config.json')
const bodyParser = require('body-parser');
const jwt_decoder = require('jwt-decode');
const axios = require('axios');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

app.set('view engine', 'handlebars');
app.set('views', './views');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.engine('handlebars', engine({
  defaultLayout: 'main',
}));

const datastore = new Datastore({
  projectId: 'api-portfolio-project-350723',
});

//Get credentials for data store
process.env['GOOGLE_APPLICATION_CREDENTIALS'] = './secrets/datastore_auth.json';

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${config.domain}/.well-known/jwks.json`
  }),

  // Validate the audience and the issuer.
  issuer: `https://${config.domain}/`,
  algorithms: ['RS256']
});

const management_token_request = {
  method: "POST",
  url: `https://${config.domain}/oauth/token`,
  data: {
    grant_type: 'client_credentials',
    client_id: config.client_ID,
    client_secret: config.client_secret,
    audience: `https://${config.domain}/api/v2/`
  }
};

const DEBUG = true;   //if true, shows debug if (DEBUG) console.logs


//-----------------------FUNCTIONS-----------------------------------


//Add entity to datastore
async function addEntity(kind, entity_info){
  const entity_key = datastore.key(kind);
  const new_entity = {
    key: entity_key,
    data: entity_info,
  };
  await datastore.save(new_entity);
  let [entity] = await datastore.get(entity_key);
  return entity;
}

//attaches id from key to the entity
function attachID(entity){
  entity.id = entity[Datastore.KEY].id;
  return entity;
}

//Creates and attaches a self URL to entity (e.g. 'http://localhost/loads/1234')
function attachSelfURL(request, entity, kinds){
  const endpoint = kinds + "/" + entity[datastore.KEY].id;
  const selfURL = request.protocol + "://" + request.get('host') + "/" + endpoint;
  entity.self = selfURL;
  return entity;
}

//Creates and attaches self URLSL to all entities (e.g. 'http://localhost/loads/1234')
function attachSelfURLs(request, entities, kinds){
  for (let i = 0; i < entities.length; i++){
    const endpoint = kinds + "/" + entities[i][datastore.KEY].id;
    const selfURL = request.protocol + "://" + request.get('host') + "/" + endpoint;
    entities[i].self = selfURL;
  }
  return entities;
}

//Create auth0 user
async function createUser(username, password, token){
  const options = {
    method: 'POST',
    url: `https://${config.domain}/api/v2/users`,
    headers: {
      authorization: "Bearer " + token
    },
    data: {
      email: username,
      password: password,
      connection: "Username-Password-Authentication"
    }
  }
  let response = await axios.request(options);
  if (DEBUG) console.log(response.data);
}

//Get list of all entities, attach self url and id before returning
//includes pagination (optional)
//Filters must be an array
async function getEntities(kind, filters, page_size, page_cursor) {

  const query = datastore.createQuery(kind);

  //Build query based on given parameters
  if (page_cursor) query.start(page_cursor);
  if (page_size) query.limit(page_size);
  if (filters)  //apply all filters
    for (let i = 0; i < filters.length; i++)
      query.filter(filters[i].property, filters[i].operator, filters[i].value);
  if (DEBUG) console.log(query);
  if (DEBUG) console.log("filters:", filters);

  //Get results with pagination
  const results = await datastore.runQuery(query);
  if (DEBUG) console.log("Results:", results);
  const entities = results[0];
  const info = results[1];

  //Get total results count without pagination
  const temp = await datastore.runQuery(query.limit(-1).start(null));
  const total_results_count = temp[0].length;

  return [entities.map(attachID), info, total_results_count];
}

//Get entity by ID
async function getEntity(kind, id){
  const key = datastore.key([kind, parseInt(id, 10)]);
  return datastore.get(key);
}

//get auth0 management token to use management API tools
async function getManagementToken(){
  const options = {
    method: "POST",
    url: `https://${config.domain}/oauth/token`,
    data: {
      grant_type: 'client_credentials',
      client_id: config.client_ID,
      client_secret: config.client_secret,
      audience: `https://${config.domain}/api/v2/`
    }
  };
  let response = await axios.request(options);
  if (DEBUG) console.log(response);
  const management_token = response.data.access_token;
  if (DEBUG) console.log("Management token:", management_token);
  return management_token;
}

//Builds a "next page" link for paginated results
function getNextPage(page_info, req){
  let next_link = "NO MORE RESULTS";
  let page_cursor = page_info.endCursor;
  if (page_info.moreResults !== Datastore.NO_MORE_RESULTS){
    next_link = req.protocol + "://" + req.get('host') 
                + "/boats/page/" + encodeURIComponent(page_cursor);
  }
  return next_link
}

//Returns self URL to entity (e.g. 'http://localhost/loads/1234')
function getSelfURL(request, entity, kinds){
  const endpoint = kinds + "/" + entity[datastore.KEY].id;
  const selfURL = request.protocol + "://" + request.get('host') + "/" + endpoint;
  return selfURL;
}

//Get all auth0 users from this app
async function getUsers(token){
  const options = {
    method: 'GET',
    url: `https://${config.domain}/api/v2/users`,
    headers: {
      authorization: "Bearer " + token
    }  
  }
  let response = await axios.request(options);
  const users = response.data;
  if (DEBUG) console.log(users);
  return users;
}

//Get auth0 user JWT token
async function getUserToken(username, password){
  const options = {
    method: 'POST',
    url: `https://${config.domain}/oauth/token`,
    data: {
      username: username,
      password: password,
      grant_type: "password",
      connection: "Username-Password-Authentication",
      client_id: config.client_ID,
      client_secret: config.client_secret
    }
  }
  let response = await axios.request(options);
  //if (DEBUG) console.log(response.data.id_token);
  if (DEBUG) console.log(response.data);
  return response.data.id_token;
}

//Takes a request object and a array of accepted types of content
function validateContentType(req, accepted_types){
  if (DEBUG) console.log("Checking for valid content-types...");
  
  const accepts = req.accepts(accepted_types);
  let error = null;
  let status_code = null;
  if (!accepts){
    status_code = 406;
    error = {"Error": "Not accepted response content-type. Must be application/json."};
  }
  
  //if (req.get('content-type') !== 'application/json'){
    //status_code = 415;
    //error = {"Error": "Invalid request content-type. Must be application/json."};
  //}
  return [status_code, error];
}

//Checks if request body has valid data (eg. correct data type, length)
function validateRequestData(req_body){
  let error = null;
  if (DEBUG) console.log("Checking if request body has valid data");

  if  ((req_body.name && typeof req_body.name !== "string") ||
       (req_body.type && typeof req_body.type !== "string") ||
       (req_body.length && isNaN(req_body.length)))
    error = {"Error": "One or more attribute has wrong data type."};
  
  else if ((req_body.name && req_body.name.length > 20) ||
           (req_body.type && req_body.type.length > 15) ||
           (req_body.length && req_body.length.length > 10))
    error = {"Error": "One or more attribute has too many characters/digits."};
  
  return error;
}


//--------------------Auth0 Login ROUTERS-----------------------------------



/*To get JWTs from auth0*/
app.get('/', function(req, res) { 
  res.render('home');
});

//Attempts to login auth0 user, or create new user.
//Gets and displays the user's auth0 JWT token
app.post('/login', async function(req, res) {
  try{
    const username = req.body.email;
    const password = req.body.password;

    //Get token to use the management API
    const management_token = await getManagementToken();
    
    //Check if user already exists
    const users = await getUsers(management_token);
    let found_user = false;
    for (let i = 0; i < users.length; i++){
      if (users[i].name === username){
        if (DEBUG) console.log("found matching username")
        found_user = true;
      }
    }
    //If user doesn't exist, create one
    if (!found_user){
      if (DEBUG) console.log("No matching user found");
      await createUser(username, password, management_token);
    } 

    //Get the JWT user token
    const user_jwt = await getUserToken(username, password);

    //Decode JWT
    const jwt_decoded = jwt_decoder(user_jwt);

    //Store user in database if new user
    if (!found_user){
      const user = {
        "name": jwt_decoded.name,
        "sub": jwt_decoded.sub
      }
      await addEntity('user', user);
    }

    //Display the encrypted JWT in the browser
    res.render('user_info', { 
      jwt: user_jwt, 
      name: jwt_decoded.name,
      sub: jwt_decoded.sub
    });

  } catch (error) {
    if (DEBUG) console.log(error);
    res.status(error.response.status).send(error.response.data);
  }
});



//--------------------------USER ROUTERS---------------------------


//Returns all users
app.get('/users', async function(req, res) {
    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(406).send(error);
      return;
    }

  const results = await getEntities('user');
  const users = results[0];
  if (DEBUG) console.log("All users:", users);
  attachSelfURLs(req, users, 'users');
  res.status(200).send(users);
});

//If attempt is made to delete loads root URL, 405 error
app.delete('/loads', async (req,res,next) => {
  res.sendStatus(405).end();
});


//-----------------------BOAT ROUTERS---------------------------------
/*Represents boat entities. Protected and accessible only by user
who created the entity.*/


//Add boat router
app.post('/boats', checkJwt, async function(req, res){
  
  try {


    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(406).send(error);
      return;
    }

    if (DEBUG) console.log(req.auth);
    const boat_info = req.body;
    boat_info.loads = [];
    boat_info.owner = req.auth.sub;
    if (DEBUG) console.log("Adding boat:", req.body);
    const boat = await addEntity('boat', req.body);
    attachID(boat);
    attachSelfURL(req, boat, 'boats');
    if (DEBUG) console.log("Boat added:", boat);
    res.status(201).send(boat);

  } catch (error) {
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//If JWT invalid for post boats request
app.use(function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
      res.status(401).send({"Error": "invalid jwt token"});
  } else {
      next(err);
  }
});

//If JWT valid, return all boats associated with that owner
app.get('/boats', checkJwt, async function(req, res) {
  try{

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    //Build paramaters to run the entity query 
    const owner_id = req.auth.sub
    const filter = [  //build query filters
      {
        property: "owner",
        operator: "=",
        value: owner_id 
      }
    ];  

    //Run query and get paginated boat entities 
    const results = await getEntities('boat', filter, 5, null);
    const boats = results[0];
    if (DEBUG) console.log("Query results:", results);
    if (DEBUG) console.log("Owner's boats:", boats);
    attachSelfURLs(req, boats, 'boats');
    const next_page_link = getNextPage(results[1], req);  //link to next page
    const total_results_count = results[2];  //total number of results of query without pagination

    //Build and send response
    const entities_with_pagination = {
      "boats": boats,
      "total entity count": total_results_count,
      "next page": next_page_link
    };
    res.status(200).send(entities_with_pagination);

  } catch (error) {
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//If JWT invalid, return an error
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, unauthorized to view boats")
    res
      .status(401)
      .send({ "Error": "Invalid JWT. Must have valid authorization to view boats."});
  } else {
      next(err);
  }
});

//If JWT valid, return all boats associated with that owner
//(For subsequent pages)
app.get('/boats/page/:page_cursor', checkJwt, async function(req, res) {
  try{

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    //Build paramaters to run the entity query 
    const owner_id = req.auth.sub
    const filter = [  //build query filters
      {
        property: "owner",
        operator: "=",
        value: owner_id 
      }
    ];  
    let page_cursor = null;
    if (req.params.page_cursor) page_cursor = req.params.page_cursor;  //get page cursor
    if (DEBUG) console.log("Page cursor:", page_cursor);

    //Run query and get paginated boat entities 
    const results = await getEntities('boat', filter, 5, page_cursor);
    const boats = results[0];
    if (DEBUG) console.log("Query results:", results);
    if (DEBUG) console.log("Owner's boats:", boats);
    attachSelfURLs(req, boats, 'boats');
    const next_page_link = getNextPage(results[1], req);  //link to next page
    const total_results_count = results[2];  //total number of results of query without pagination

    //Build and send response
    const entities_with_pagination = {
      "boats": boats,
      "total entity count": total_results_count,
      "next page": next_page_link
    };
    res.status(200).send(entities_with_pagination);

  } catch (error) {
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//If JWT invalid, return an error
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, unauthorized to view boats")
    res
      .status(401)
      .send({ "Error": "Invalid JWT. Must have valid authorization to view boats."});
  } else {
      next(err);
  }
});

//If JWT valid, return boat with given id 
app.get('/boats/:boat_id', checkJwt, async function(req, res) {
  try{
    
    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    //Build paramaters to run the entity query 
    const owner_id = req.auth.sub;
    const boat_id = req.params.boat_id;

    const [boat] = await getEntity('boat', boat_id);

    if (!boat){
      if (DEBUG) console.log("No boat found with given id!");
      res.status(404).send({"Error": "No boat found for given ID"});
      return;
    }

    if (boat.owner !== owner_id){
      res.status(401).send({"Error": "Boat belongs to another user"});
      return;
    }

    if (DEBUG) console.log("Found boat:", boat);
    attachSelfURL(req, boat, 'boats');
    attachID(boat);
    res.status(200).send(boat);
  } catch(error){
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//If JWT invalid, return an error
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, unauthorized to view boats")
    res
      .status(401)
      .send({ "Error": "Invalid JWT. Must have valid authorization to view boats."});
  } else {
      next(err);
  }
});

//Update SOME of a boat's attributes
app.patch('/boats/:id', checkJwt, async (req, res, next) => {
  try {

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    const boat_update = req.body;

    //Must not be updating ALL attributes (that's for PUT not PATCH)
    if (boat_update.name && boat_update.type && boat_update.length){
      if (DEBUG) console.log("Update failed. PATCH updates only some attributes. Use PUT to edit ALL attributes.");
      status_code = 400;
      error = {"Error": "Cannot use PATCH to update all attributes. Use PUT instead."}
      res.status(status_code).send(error);
      return;
    }

    //Try to find boat with given ID
    if (DEBUG) console.log("Looking for ID:", req.params.id);
    const [boat] = await getEntity('boat', req.params.id);
    if (!boat){
      if (DEBUG) console.log(`No boat with ID ${req.params.id} found.`);
      status_code = 404;
      error = {"Error": "No boat with this boat_id exists"};
      res.status(status_code).send(error);   
      return;  
    }

    //Verify boat belongs to this user
    if (DEBUG) console.log("Verifying owner is correct");
    const owner_id = req.auth.sub;
    if (boat.owner !== owner_id){
      if (DEBUG) console.log("User does not own this boat! Patch request denied.");
      res.status(401).send({"Error": "You cannot edit someone else's boat."});
      return;
    }
      
    //if request is OK, update boat (only update attributes from request)
    if (boat_update.name)
      boat.name = boat_update.name;
    if (boat_update.type)
      boat.type = boat_update.type;
    if (boat_update.length)
      boat.length = boat_update.length;
    await datastore.update(boat);
    status_code = 200;
    attachSelfURL(req, boat, 'boats');
    attachID(boat);
    res.status(status_code).send(boat);

  } catch(error){
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//If JWT invalid, return an error
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, unauthorized to view boats")
    res
      .status(401)
      .send({ "Error": "Invalid JWT. Must have valid authorization to view boats."});
  } else {
      next(err);
  }
});

//Update ALL of a boat's attributes
app.put('/boats/:id', checkJwt, async (req, res, next) => {
  try {

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    const boat_update = req.body;

    //Must be updating ALL attributes (otherwise should use PATCH)
    if (!boat_update.name || !boat_update.type || !boat_update.length){
      if (DEBUG) console.log("Update failed. Required attributes missing. PUT must update all attributes.");
      status_code = 400;
      error = {"Error": "Request missing at least one required attritube to update. Must update all attributes."}
      res.status(status_code).send(error);
      return;
    }

    //ID must not be edited by this request
    if (boat_update.id){
      if (DEBUG) console.log("Cannot change ID");
      status_code = 400;
      error = {"Error": "Changing ID of entity is forbidden"}
      res.status(status_code).send(error);
      return;
    }

    //Try to find boat with given ID
    console.log("Looking for ID:", req.params.id);
    const [boat] = await getEntity('boat', req.params.id);
    if (!boat){
      if (DEBUG) console.log(`No boat with ID ${req.params.id} found.`);
      status_code = 404;
      error = {"Error": "No boat with this boat_id exists"};
      res.status(status_code).send(error);   
      return;  
    }

    //Verify boat belongs to this user
    if (DEBUG) console.log("Verifying owner is correct");
    const owner_id = req.auth.sub;
    if (boat.owner !== owner_id){
      if (DEBUG) console.log("User does not own this boat! Patch request denied.");
      res.status(401).send({"Error": "You cannot edit someone else's boat."});
      return;
    }

    //if request is OK, update boat
    boat.name = boat_update.name;
    boat.type = boat_update.type;
    boat.length = boat_update.length;
    await datastore.update(boat);
    status_code = 303;
    attachSelfURL(req, boat, 'boats');
    attachID(boat);
    res
      .status(status_code)
      .send(boat);

    } catch (error) {
      next(error);
    }
});

//If JWT invalid, return an error
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, unauthorized to view boats")
    res
      .status(401)
      .send({ "Error": "Invalid JWT. Must have valid authorization to view boats."});
  } else {
      next(err);
  }
});

app.delete('/boats/:boat_id', checkJwt, async function(req, res) {

  try{
    const boat_id = req.params.boat_id;
    const owner_id = req.auth.sub;
    if (DEBUG) console.log("Looking for ID:", boat_id);
    const [boat] = await getEntity('boat', boat_id);

    //If no boat with ID found
    if (!boat){
      if (DEBUG) console.log(`No boat with ID ${boat_id} found.`);
      res
        .status(403)
        .set('Content-Type', 'application/json')
        .send({"Error": "No boat with this boat_id exists"})
        .end();
        return;      
    }
    
    //If boat found, check if it belongs to this owner
    if (DEBUG) console.log("Found boat:", boat);
    if (DEBUG) console.log("checking if boat belongs to this owner...");
    if (boat.owner !== owner_id){
      if (DEBUG) console.log("Boat found, but belongs to different owner");
      res
        .status(403)
        .set('Content-Type', 'application/json')
        .send({"Error": "Boat owned by someone else."})
        .end();
        return;
    }

    //Unload any loads before deleting the boat
    const loads = boat.loads;
    if (DEBUG) console.log("Removing these loads from boat before deleting:", loads);
    for (let i = 0; i < loads.length; i++){
      //if (DEBUG) console.log("current load:", loads[i].id);
      let [load] = await getEntity('load', loads[i].id);
      //if (DEBUG) console.log("Removing carrier from load:", load);
      load.carrier = null;
      await datastore.update(load);
    }

    //If request OK, delete the boat
    const boat_key = boat[Datastore.KEY];
    datastore.delete(boat_key, (err, apiResp) => {
      if (err)
        if (DEBUG) console.log(err);
      if (DEBUG) console.log("Datastore delete api response:", apiResp);
    });
    if (DEBUG) console.log(`Boat ${boat_id} successfully deleted.`);
    res
      .status(204)
      .set('Content-Type', 'application/json')
      .end();

  } catch(error){
  if (DEBUG) console.log(error);
  res.send(error);
  }
});

//If JWT invalid, do not delete boat. Send error
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, delete request refused.")
    res.status(401).send({"Error": "JWT invalid, delete request denied."});
  } else {
      next(err);
  }
});


//If attempt is made to delete boat root URL, 405 error
app.delete('/boats', async (req,res,next) => {
  res.sendStatus(405).end();
});

//-----------------------LOAD ROUTERS---------------------------------
//Represents loads that can be loaded onto carriers (boats)
//Unprotected entity


//Add a load


app.post('/loads', async (req, res, next) => {
  
    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

  console.log("Adding load:", req.body);
  const load_info = req.body;
  load_info.carrier = null;  //loads always start with no carrier (boat)
  //check for missing requirements
  if (!load_info.volume || !load_info.item || !load_info.creation_date){
    console.log("Add load failed. One or more required attributes missing.");
    res
      .status(400)
      .set('Content-Type', 'application/json')
      .send({"Error": "The request object is missing at least one of the required attributes"})
      .end();
    } else {
  //if all requirements present, add load
    try {
      const load = await addEntity('load', load_info);  //create and save new entity
      attachID(load);   //attach entity ID to response
      attachSelfURL(req, load, 'loads');  //attach self URL to the response
      console.log("Created load and attached ID and Self:", load);
    res
      .status(201)
      .set('Content-Type', 'application/json')
      .send(load)
      .end();
    } catch (error) {
      next(error);
    }
  }
});

//Get list of all loads (first page, no cursor given)
app.get('/loads', async (req, res, next) => {
  try {

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }


    let results = await getEntities('load', null, 5, null);
    const info = results[1];
    const loads = results[0];
    const cursor = info.endCursor;
    console.log("Info:", info);
    attachSelfURLs(req, loads, 'loads');
    let next_link = "NO MORE RESULTS";
    if (info.moreResults !== Datastore.NO_MORE_RESULTS)
      next_link = req.protocol + "://" + req.get('host') + "/loads/page/" + encodeURIComponent(cursor);
    const resp = {
      "loads": loads,
      "next": next_link
    }
    //results = [loads, cursor];
    //console.log("All loads:", loads);
    res
      .status(200)
      .set('Content-Type', 'application/json')
      .send(resp)
      .end();
  } catch (error) {
    next(error);
  }
});

//Get list of all loads if a cursor is given for pagination
app.get('/loads/page/:page_cursor', async (req, res, next) => {
  try {

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    let results = await getEntities('load', null, 5, req.params.page_cursor);
    const info = results[1];
    const loads = results[0];
    const cursor = info.endCursor;
    console.log("Info:", info);
    attachSelfURLs(req, loads, 'loads');
    let next_link = "NO MORE RESULTS";
    if (info.moreResults !== Datastore.NO_MORE_RESULTS)
      next_link = req.protocol + "://" + req.get('host') + "/loads/page/" + encodeURIComponent(cursor);
    const resp = {
      "loads": loads,
      "next": next_link
    }
    //results = [loads, cursor];
    //console.log("All loads:", loads);
    res
      .status(200)
      .set('Content-Type', 'application/json')
      .send(resp)
      .end();
  } catch (error) {
    next(error);
  }
});

//Get load by ID
app.get('/loads/:id', async (req, res, next) => {
  try {

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    console.log("Looking for ID:", req.params.id);
    const [load] = await getEntity('load', req.params.id);
    if (!load){
      console.log(`No load with ID ${req.params.id} found.`)
      res
        .status(404)
        .set('Content-Type', 'application/json')
        .send({"Error": "No load with this load_id exists"})
        .end();
    } else {
      console.log("Found matching load:", load);
      attachID(load);
      attachSelfURL(req, load, 'loads');
      res
        .status(200)
        .set('Content-Type', 'application/json')
        .send(attachID(load))
        .end();
      }
    } catch (error) {
      next(error);
    }
});

//Update some of a load's attributes
app.patch('/loads/:id', checkJwt, async (req, res, next) => {
  try {

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    const load_update = req.body;

    //ID must not be edited by this request
    if (load_update.id){
      if (DEBUG) console.log("Cannot change ID");
      status_code = 400;
      error = {"Error": "Changing ID of entity is forbidden"}
      res.status(status_code).send(error);
      return;
    }

    //Must not be updating ALL attributes (that's for PUT not PATCH)
    if (load_update.volume && load_update.item && load_update.creation_date){
      if (DEBUG) console.log("Update failed. PATCH updates only some attributes. Use PUT to edit ALL attributes.");
      status_code = 400;
      error = {"Error": "Cannot use PATCH to update all attributes. Use PUT instead."}
      res.status(status_code).send(error);
      return;
    }

    //Try to find load with given ID
    if (DEBUG) console.log("Looking for ID:", req.params.id);
    const [load] = await getEntity('load', req.params.id);
    if (!load){
      if (DEBUG) console.log(`No load with ID ${req.params.id} found.`);
      status_code = 404;
      error = {"Error": "No load with this load_id exists"};
      res.status(status_code).send(error);   
      return;  
    }

    //If load on carrier, verify boat owner is editing load
    if (DEBUG) console.log("Verifying owner is correct");
    const owner_id = req.auth.sub;
    if (load.carrier.owner !== owner_id){
      if (DEBUG) console.log("User does not own this boat! Load patch request denied.");
      res.status(401).send({"Error": "You cannot edit loads on boats you do not own."});
      return;
    }
      
    //if request is OK, update load (only update attributes from request)
    if (load_update.volume)
      load.volume = load_update.volume;
    if (load_update.item)
      load.item = load_update.item;
    if (load_update.creation_date)
      load.creation_date = load_update.creation_date;
    await datastore.update(load);
    status_code = 200;
    attachID(load);
    attachSelfURL(req, load, 'loads');
    res.status(status_code).send(load);

  } catch(error){
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//Update all of a load's attributes
app.put('/loads/:id', checkJwt, async (req, res, next) => {
  try {

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    const load_update = req.body;

    //ID must not be edited by this request
    if (load_update.id){
      if (DEBUG) console.log("Cannot change ID");
      status_code = 400;
      error = {"Error": "Changing ID of entity is forbidden"}
      res.status(status_code).send(error);
      return;
    }

    //Verify all attributes being updated (not just some)
    if (DEBUG) console.log("Verifying all attributes being updated");
    if (!load_update.volume || !load_update.item || !load_update.creation_date){
      if (DEBUG) console.log("Update failed. PUT updates all attributes. Use PATCH to edit some attributes.");
      status_code = 400;
      error = {"Error": "Cannot use PUT to update some attributes. Use PATCH instead."}
      res.status(status_code).send(error);
      return;
    }

    //Try to find load with given ID
    if (DEBUG) console.log("Looking for ID:", req.params.id);
    const [load] = await getEntity('load', req.params.id);
    if (!load){
      if (DEBUG) console.log(`No load with ID ${req.params.id} found.`);
      status_code = 404;
      error = {"Error": "No load with this load_id exists"};
      res.status(status_code).send(error);   
      return;  
    }

    //If load on carrier, verify boat owner is editing load
    if (DEBUG) console.log("Verifying owner is correct");
    const owner_id = req.auth.sub;
    if (load.carrier.owner !== owner_id){
      if (DEBUG) console.log("User does not own this boat! Load patch request denied.");
      res.status(401).send({"Error": "You cannot edit loads on boats you do not own."});
      return;
    }

    //if request is OK, update load
    await datastore.update(load);
    status_code = 303;
    attachID(load);
    attachSelfURL(req, load, 'loads');
    res.status(status_code).send(load);

  } catch(error){
    if (DEBUG) console.log(error);
    res.send(error);
  }
});


//Delete a load
app.delete('/loads/:id', async (req, res, next) => { 
  try{
    const load_id = req.params.id;
    console.log("Looking for ID:", load_id);
    const [load] = await getEntity('load', load_id);

    //If no load with ID found
    if (!load){
      console.log(`No load with ID ${load_id} found.`);
      res
        .status(404)
        .set('Content-Type', 'application/json')
        .send({"Error": "No load with this load_id exists"})
        .end();      
    } else {
      console.log("Found matching load key:", load);

      //First, remove load from boat, if it's loaded on one
      const boat_id = load.carrier.id;
      const [boat] = await getEntity('boat', boat_id);
      if (boat.loads){
        //console.log("Current boat loads:", boat.loads);
        for (let i = 0; i < boat.loads.length; i++){
          if (boat.loads[i].id === load_id){
            boat.loads.splice(i, 1);
            //console.log("Boat loads after removing load:", boat.loads);
            await datastore.update(boat);
          }
        }
      }

      const key = load[Datastore.KEY];
      datastore.delete(key, (err, apiResp) => {
        if (err)
          console.log(err);
        console.log("Datastore delete api response:", apiResp);
      });
      console.log(`Slip ${load_id} successfully deleted.`);
      res
        .status(204)
        .set('Content-Type', 'application/json')
        .end();
    }
  } catch(error){
    console.log(error);
    next(error);
  }
});


//If attempt is made to delete loads root URL, 405 error
app.delete('/loads', async (req,res,next) => {
  res.sendStatus(405).end();
});



//-------------BOAT & LOADER RELATIONSHIP ROUTERS---------------
//Protected, accessible by boat owner


//get all loads for a given boat
app.get('/boats/:boat_id/loads/', checkJwt, async (req, res, next) => {
  try{
    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }
    
    
    //Get the requested boat
    const [boat] = await getEntity('boat', req.params.boat_id);
    console.log("Found boat:", boat);

    //Make sure requested boat exists
    if (!boat){
      console.log("boat doesn't exist");
      res
        .status(404)
        .set('Content-Type', 'application/json')
        .send({"Error": "The specified boat does not exist"})
      return;    
    }

    //Make sure boat belongs to this user
    const owner_id = req.auth.sub;
    if (boat.owner !== owner_id){
      res.status(401).send({"Error": "Boat belongs to another user"});
      return;
    }

    //Get and return all loads from this boat
    const loads = [];
    for (let i = 0; i < boat.loads.length; i++){
      let [load] = await getEntity('load', boat.loads[i].id);
      attachID(load);
      attachSelfURL(req, load, 'loads');
      loads.push(load);
    }
    if (DEBUG) console.log("All loads for boat:", loads);

    res
      .status(200)
      .set('Content-Type', 'application/json')   
      .send(loads);
    return;

  } catch(error){
    console.log(error);
    next(error);
  }
});

//If JWT invalid
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, delete request refused.")
    res.status(401).send({"Error": "JWT invalid, delete request denied."});
  } else {
      next(err);
  }
});

//assign load to boat
app.put('/boats/:boat_id/loads/:load_id', checkJwt, async (req, res, next) => { 
  try{

    //Validate "accepts" is application/json
    let status_code = null;
    let error = null;
    [status_code, error] = validateContentType(req, 'application/json');
    //console.log("accepts content:", results);
    if (error){
      if (DEBUG) console.log("Invalid request accepts type")
      res.status(status_code).send(error);
      return;
    }

    //Get the requested load
    const [load] = await getEntity('load', req.params.load_id);
    console.log("Found load:", load);

    //Get the requested boat
    const [boat] = await getEntity('boat', req.params.boat_id);
    console.log("Found boat:", boat);

    //Make sure requested load and boat exist
    if (!load || !boat){
      console.log("Load/boat doesn't exist");
      res
        .status(404)
        .set('Content-Type', 'application/json')
        .send({"Error": "The specified boat and/or load does not exist"})
        .end();      
    }

    //Make sure boat belongs to this user
    const owner_id = req.auth.sub;
    if (boat.owner !== owner_id){
      res.status(401).send({"Error": "Boat belongs to another user"});
      return;
    }

    //If load already assigned to another boat
    else if(load.carrier) {
      console.log("Load already assigned to another boat");
      res
        .status(403)
        .set('Content-Type', 'application/json')
        .send({"Error": "The load is already loaded on another boat"})
        .end();   
    }

    //If load and boat exists, and load isn't already assigned, add load to boat
    else {

      boat.loads.push({  //add load info to boat.loads
        "id": load[datastore.KEY].id,
        "self": getSelfURL(req, load, 'loads')
      });
      load.carrier = {   //add boat info to load.carrier
        "id": boat[datastore.KEY].id,
        "name": boat.name,
        "self": getSelfURL(req, boat, 'boats'),
        "owner": owner_id
      };
      console.log("Updated boat info:", boat);
      console.log("Updated load info:", load);

      await datastore.update(boat);
      await datastore.update(load);
      console.log(`Added load ${load[datastore.KEY].id} to boat ${boat[datastore.KEY].id}`);
      res
        .status(204)
        .set('Content-Type', 'application/json')
        .end();   
    }
  } catch(error){
    console.log(error);
    next(error);
  }
});

//If JWT invalid
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, load assignment request refused.")
    res.status(401).send({"Error": "JWT invalid, load assignment request denied."});
  } else {
      next(err);
  }
});

//Remove load from boat
app.delete('/boats/:boat_id/loads/:load_id', async (req, res, next) => { 
  try{

    //Get the requested load
    const [load] = await getEntity('load', req.params.load_id);
    console.log("Found load:", load);

    //Get the requested boat
    const [boat] = await getEntity('boat', req.params.boat_id);
    console.log("Found boat:", boat);

    //If boat or load don't exist
    if (!boat || !load){
      console.log("No boat with this boat_id is loaded with the load with this load_id");
      res
        .status(404)
        .set('Content-Type', 'application/json')
        .send({"Error": "No boat with this boat_id is loaded with the load with this load_id"})
        .end();    
      return;  
    }

    //If boat found, check if it belongs to this owner
    const owner_id = req.auth.sub;
    if (DEBUG) console.log("Found boat:", boat);
    if (DEBUG) console.log("checking if boat belongs to this owner...");
    if (boat.owner !== owner_id){
      if (DEBUG) console.log("Boat found, but belongs to different owner");
      res
        .status(401)
        .set('Content-Type', 'application/json')
        .send({"Error": "Boat owned by someone else."})
        .end();
        return;
    }

    //Determine if requested removed load is actually on given boat
    let found_load = null;
    const load_id = req.params.load_id;
    if (boat.loads){
      console.log("Loads on boat:", boat.loads);
      console.log("Load carrier:", load.carrier);  
      for (let i = 0; i < boat.loads.length; i++){
        if (boat.loads[i].id = load_id){
          found_load = boat.loads[i].id; //if we find the load on the boat
          boat.loads.splice(i, 1); //remove load from boat loads
        }
      }
    }

    //If load isn't on the boat
    if (!found_load){
      console.log("No boat with this boat_id is loaded with the load with this load_id");
      res
        .status(404)
        .set('Content-Type', 'application/json')
        .send({"Error": "No boat with this boat_id is loaded with the load with this load_id"})
        .end();      
    }

    //If load and boat exists, remove load from boat
    else {
      //boat.loads = boat_loads;  //remove load from boat
      load.carrier = null;  //remove boat from load
      await datastore.update(boat);
      await datastore.update(load);
      console.log(`Removed load ${load[datastore.KEY].id} from boat ${boat[datastore.KEY].id}`);
      res
        .status(204)
        .set('Content-Type', 'application/json')
        .end();   
    }
  } catch(error){
    console.log(error);
    next(error);
  }
});

//If JWT invalid
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, remove load request refused.")
    res.status(401).send({"Error": "JWT invalid, load removal request denied."});
  } else {
      next(err);
  }
});

//------------------------RUN APP----------------------------------


const PORT = parseInt(parseInt(process.env.PORT)) || 8080;
app.listen(PORT, () => {
  if (DEBUG) console.log(`App listening on port ${PORT}`);
  if (DEBUG) console.log('Press Ctrl+C to quit.');
});

module.exports = app;
