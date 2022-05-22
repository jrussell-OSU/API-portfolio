
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
async function getEntities(kind, filter, page_size, page_cursor) {

  const query = datastore.createQuery(kind);

  //Build query based on given parameters
  if (page_cursor) query.start(page_cursor);
  if (filter) query.filter(filter.property, filter.operator, filter.value);
  if (page_size) query.limit(page_size);
  if (DEBUG) console.log("Query:", query);

  const results = await datastore.runQuery(query);
  if (DEBUG) console.log("Results:", results);
  const entities = results[0];
  const info = results[1];

  return [entities.map(attachID), info];
}

//Returns all public entities
async function getPublicEntities(kind){
  let query = datastore.createQuery(kind);
  let all_entities = [];
  await datastore.runQuery(query).then((entities) => {
    all_entities = entities[0].map(attachID);
  });
  //if (DEBUG) console.log("all entities:", all_entities);
  const private_entities = [];
  for (let i = 0; i < all_entities.length; i++){
    if (all_entities[i].public === true)
      private_entities.push(all_entities[i]);
  }
  return private_entities;
}

//Returns all entities for an owner
async function getOwnerEntities(kind, owner_id){
  let query = datastore.createQuery(kind);
  let all_entities = [];
  await datastore.runQuery(query).then((entities) => {
    all_entities = entities[0].map(attachID);
  });
  //if (DEBUG) console.log("all entities:", all_entities);
  const owner_entities = [];
  for (let i = 0; i < all_entities.length; i++){
    if (all_entities[i].owner === owner_id)
      owner_entities.push(all_entities[i]);
  }
  return owner_entities;
}

//Returns only public entities for an owner
async function getOwnerPublicEntities(kind, owner_id){
  let query = datastore.createQuery(kind);
  let all_entities = [];
  await datastore.runQuery(query).then((entities) => {
    all_entities = entities[0].map(attachID);
  });
  if (DEBUG) console.log("all entities:", all_entities);
  const owner_entities = [];
  for (let i = 0; i < all_entities.length; i++){
    if (all_entities[i].owner === owner_id &&
        all_entities[i].public === true)
      owner_entities.push(all_entities[i]);
  }
  return owner_entities;
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

//------------------------ROUTERS-----------------------------------


//Render the home page
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

//Get all boats (public and private) for owner if valid JWT
app.get('/owners/:owner_id/boats/:page_cursor?', checkJwt, async function(req, res){
  try{
    //Set up query filter
    const owner_id = req.params.owner_id;
    const filter = {
      property: "owner",
      operator: "=",
      value: owner_id
    };  
    let page_cursor = null;
    if (req.params.page_cursor) page_cursor = req.params.page_cursor;
    if (DEBUG) console.log("Page cursor:", page_cursor);
    const page_size = 5;

    //Get boat entities 
    const results = await getEntities('boat', filter, page_size, page_cursor);
    const boats = results[0];
    page_cursor = results[1].endCursor;
    if (DEBUG) console.log("Query results:", results);
    if (DEBUG) console.log("Owner's boats:", boats);
    attachSelfURLs(req, boats, 'boats');

    //Add next page link if there is one
    let next_link = "NO MORE RESULTS";
    if (results[1].moreResults !== Datastore.NO_MORE_RESULTS){
      next_link = req.protocol + "://" + req.get('host') 
                  + "/owners/" + owner_id + "/boats/"
                  + encodeURIComponent(page_cursor);
    }

    const resp = {
      "boats": boats,
      "next": next_link
    }
    res.status(200).send(resp);

  } catch (error) {
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//If JWT invalid, return only owner's *public* boats
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("bad jwt for get owner's boats request, return only owner's public boats");
    const owner_id = req.url.slice(8, 38);
    const boats = await getOwnerPublicEntities('boat', owner_id);
    if (DEBUG) console.log("owner's public boats boats:", boats);
    attachSelfURLs(req, boats, 'boats');
    res.status(200).send(boats);
  } else {
      next(err);
  }
});

//If JWT valid, return all boats associated with that owner
app.get('/boats', checkJwt, async function(req, res) {
  try{
    const owner_id = req.auth.sub;
    const boats = await getOwnerEntities('boat', owner_id);
    if (DEBUG) console.log("All owner's boats:", boats);
    attachSelfURLs(req, boats, 'boats');
    res.status(200).send(boats);
  } catch(error){
    if (DEBUG) console.log(error);
    res.send(error);
  }
});

//If JWT invalid, return all public boats from all owners
app.use(async function (err, req, res, next) {
  console.error(err);
  if (err.name === "UnauthorizedError") {
    if (DEBUG) console.log("Invalid JWT token, responding with all public boats.")
    const boats = await getPublicEntities('boat');
    if (DEBUG) console.log("all public boats boats:", boats);
    attachSelfURLs(req, boats, 'boats');
    res.status(200).send(boats);
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
