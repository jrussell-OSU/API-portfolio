
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
const axios = require('axios');
const super_string = require('@supercharge/strings');  //use with .random() to create random strings
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

//get auth0 management token to use management API tools
async function get_management_token(){
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

//Get all auth0 users from this app
async function get_users(token){
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

//Create auth0 user
async function create_user(username, password, token){
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

//Get auth0 user JWT token
async function get_user_token(username, password){
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

//Returns self URL to entity (e.g. 'http://localhost/loads/1234')
function getSelfURL(request, entity, kinds){
  const endpoint = kinds + "/" + entity[datastore.KEY].id;
  const selfURL = request.protocol + "://" + request.get('host') + "/" + endpoint;
  return selfURL;
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
  
  if (req.get('content-type') !== 'application/json'){
    status_code = 415;
    error = {"Error": "Invalid request content-type. Must be application/json."};
  }
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

//Builds a "next page" link for paginated results
function get_next_page(page_info, req){
  let next_link = "NO MORE RESULTS";
  let page_cursor = page_info.endCursor;
  if (page_info.moreResults !== Datastore.NO_MORE_RESULTS){
    next_link = req.protocol + "://" + req.get('host') 
                + "/boats/page/" + encodeURIComponent(page_cursor);
  }
  return next_link
}


//------------------------ROUTERS-----------------------------------


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
    const management_token = await get_management_token();
    
    //Check if user already exists
    const users = await get_users(management_token);
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
      await create_user(username, password, management_token);
    } 

    //Get the JWT user token
    const user_jwt = await get_user_token(username, password);

    //Display the encrypted JWT in the browser
    res.render('user_info', { jwt: user_jwt });

  } catch (error) {
    if (DEBUG) console.log(error);
    res.status(error.response.status).send(error.response.data);
  }
});

//Add boat router
app.post('/boats', checkJwt, async function(req, res){
  
  try {

    let status_code = null;
    let error = null;

    //Validate that request input data is valid
    error = validateRequestData(req.body);
    if (error){
      if (DEBUG) console.log("Invalid request input data")
      res.status(400).send(error);
      return;
    }

    if (DEBUG) console.log(req.auth);
    const boat_info = req.body;
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
    const next_page_link = get_next_page(results[1], req);  //link to next page
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
    const next_page_link = get_next_page(results[1], req);  //link to next page
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
app.patch('/boats/:id', async (req, res, next) => {
  try {

    let status_code = null;
    let error = null;
    
    //Validate that request input data is valid
    error = validateRequestData(req);
    if (error){
      if (DEBUG) console.log("Invalid request input data")
      res.status(400).send(error);
      return;
    }

    const boat_update = req.body;

    //Validate request and response content-types are valid
    [status_code, error] = validateContentType(req, "application/json");
    if (status_code || error){
      if (DEBUG) console.log("Content type error found");
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
    res.status(status_code).send(attachID(boat));

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

//Update ALL of a boat's attributes
app.put('/boats/:id', async (req, res, next) => {
  try {

    let status_code = null;
    let error = null;
    
    //Validate that request input data is valid
    error = validateRequestData(req);
    if (error){
      if (DEBUG) console.log("Invalid request input data")
      res.status(400).send(error);
      return;
    }

    const boat_update = req.body;

    //Validate request and response content-types are valid
    [status_code, error] = validateContentType(req, "application/json");
    if (status_code || error){
      if (DEBUG) console.log("Content type error found");
      res.status(status_code).send(error);
      return;
    }

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

    //Check for duplicate boat names
    const is_unique_name = await uniqueNameCheck(boat_update.name, 'boat');
    if (!is_unique_name){
      if (DEBUG) console.log("Name is a duplicate, boat not added.");
      status_code = 403;
      error = {"Error": "Duplicate names not allowed."};
      res.status(403).send(error);
      return;
    }

    //if request is OK, update boat
    boat.name = boat_update.name;
    boat.type = boat_update.type;
    boat.length = boat_update.length;
    await datastore.update(boat);
    status_code = 303;
    const location = getSelfURL(req, boat, 'boats');  //put self URL for entity in content-location header
    res.set("Content-Location", location).status(status_code).send(attachID(boat));

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

//------------------------RUN APP----------------------------------

const PORT = parseInt(parseInt(process.env.PORT)) || 8080;
app.listen(PORT, () => {
  if (DEBUG) console.log(`App listening on port ${PORT}`);
  if (DEBUG) console.log('Press Ctrl+C to quit.');
});

module.exports = app;
