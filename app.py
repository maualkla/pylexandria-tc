## Flask API for adminde-tc project.
## Pylexandria Project.
## Coded by: Mauricio Alcala (@maualkla)
## Creation Date: May 2023.
## Current Version: 0.02
## Last Modification Date: feb 2024.
## More info at @intmau in twitter or in http://maualkla.com
## Description: API for the services required by the adminde-tc proyect.

## Imports
from flask import Flask, jsonify, request
from firebase_admin import credentials, firestore, initialize_app
from google.cloud.firestore_v1.base_query import FieldFilter
from config import Config
from utilities.helpers import Helpers
import rsa, bcrypt, base64, json

## Initiate Public and private key
publicKey, privateKey = rsa.newkeys(512)

## Initialize Flask App
app = Flask(__name__)

## Setup env vars
app.config.from_object(Config)

## Logging 
logging = app.config['LOGGING']

## Initialize Firestone DB
cred = credentials.Certificate('key.json')
pattern = app.config['PATTERN']
default_app = initialize_app(cred)
db = firestore.client()
users_ref = db.collection('users')
tokens_ref = db.collection('tokens')
trx_ref = db.collection('transactions')
wsp_ref = db.collection('workspaces')
sess_ref = db.collection('sessions')

## Session Service
@app.route('/session', methods=['GET', 'POST', 'DELETE'])
def session():
    try:
        ## Method: GET /session
        if request.method == 'GET':
            ## validate the required params for the service to return a valid response.
            _authorized = True if request.headers.get('SessionId') and request.headers.get('browserVersion') and request.headers.get('clientIP') else False
            ## If all the required params are there, the _auth variable is True, Else is False.
            if _authorized:
                ## Go and search for the Session Id in the request. 
                ## @TODO in this place we should add a validation to get more than one session in the future.
                _sess = sess_ref.document(request.headers.get('SessionId')).get().to_dict()
                ## In case _session exists
                if _sess != None:
                    ## Validate the client version and ip are the same. 
                    if _sess['clientVersion'] == request.headers.get('browserVersion') and _sess['clientIp'] == request.headers.get('clientIp'):
                        ## if client version and ip are the same, the response is build and send back to the requester
                        _json_data_block = {"items": []}
                        _json_data_block["items"].append(_sess)
                        _json_data_block["limit"] = 1
                        _json_data_block["count"] = 1
                        _json_data_block["containsData"] = True 
                        _json_data_block["query"] = ""
                        return jsonify(_json_data_block), 200
                    else:
                        ## if client version or ip are not same as recorded in backend, session is deleted and user has to 
                        ## login back again creating a new session. 
                        deleteSession(request.headers.get('SessionId'))
                        return jsonify({"status": "error", "code": 401, "reason": "Invalid authorization "}), 401
                else: 
                    ## In case there is no session with that session id returns 401
                    return jsonify({"status": "error", "code": 401, "reason": "Invalid authorization "}), 401
            else:
                ## in case, missing parameters to start the flow.
                return jsonify({"status": "Error", "code": 422, "reason": "Missing Required Authentication"}), 422
        ## Method: POST /session (New Login)
        elif request.method == 'POST': 
            ## Validate if the required structure is present.
            _requested_params = True if request.json['requestString'] and request.json['client'] else False
            if _requested_params:
                ## Get the params from the verified structure (decoding the requestString)
                _decoded_str = Helpers.b64Decode(request.json['requestString'])
                ## spliting the string into the un [0] and pass [1]
                _sess_params = _decoded_str.split("_")
                _client = request.json['client']
                ## Validating the values are there and are valid to proceed.
                if _sess_params[0] and _sess_params[1] and _client['ip'] and _client['browser']:
                    ## Get user reference and seach for the user on the request.
                    _user = users_ref.document(_sess_params[0]).get().to_dict()
                    ## if user not found, user will = None and will send 400 for security reasons, else it will continue
                    if _user != None:
                        ## The password gets encrypted and decoded. Then we delete the internal value of the password for security reasons
                        _requ = encrypt(_sess_params[1]).decode('utf-8')
                        _sess_params[1] = ""
                        ## Get the firebase_response_user object. It also is decoded.
                        _fire = _user['pass'].decode('utf-8')
                        ## Generate the ID for this session.
                        _idg = Helpers.idGenerator(15)
                        ## Validate if the pass is the same in the request as it is in the firebase_object
                        if _requ == _fire:
                            ## Get the user token. In case exist it will retrieve the tokenId. Else return False.
                            _token = authGet(_sess_params[0])
                            ## Validate if valid token. is present. If not, generates a new token for the user.
                            if _token == False:  
                                ## calls authPost sending user name and False. To generate a temporal token.
                                _token = authPost(_sess_params[0], False)
                            ## Generate the json object required to create the session object.
                            _session_json = {
                                "clientIp" : _client['ip'],
                                "clientVersion": _client['browser'],
                                "id": _idg,
                                "tokenId": _token['id'],
                                "userId": _sess_params[0]
                            }
                            try:
                                ## Call to create the workspace.
                                sess_ref.document(_idg).set(_session_json)
                            except Exception as e:
                                ## In case of an error updating the user, retrieve a error message.
                                print('(!) >> Handled external service exception: ' + str(e) )
                                return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "Session object failed to be created."}), 500
                            ## In case session was created successflly returns trx code and session id
                            return jsonify({"_session_id": _idg, "trxId": transactionPost(_sess_params[0], False, 1, "Session Post")}), 200
                        else:
                            ## in case passwords do not match
                            return jsonify({"status": "Error", "code": 400, "reason": "User/Pass incorrect."}), 400
                    else:
                        ## in case user is not registered.
                        return jsonify({"status": "Error", "code": 400, "reason": "User/Pass incorrect."}), 400
                else:
                    ## In case of structure not compliying with what is requested.
                    return jsonify({"status": "Error", "code": 403, "reason": "Missing Requested Parameters"}), 403
            else:
                ## In case params are not present
                return jsonify({"status": "Error", "code": 422, "reason": "Missing Required Data Structure"}), 422
        ## Method: DELETE /session (new logout)
        elif request.method == 'DELETE': 
            ## Validate if SessionId was sent as header. True if yes, else will set False.
            _requested_params = True if request.headers.get('SessionId') else False
            ## Validate the flow 
            if _requested_params:
                ## If requested parameter exist, delete the session.
                _deleted = deleteSession(request.headers.get('SessionId'))
                ## returns a 200 signaling the session end
                return jsonify({"status": "logued Out", "deleted": _deleted}), 200
            else:
                ## In case requested params not present
                return jsonify({"status": "Error", "code": 403, "reason": "Missing Requested Parameters"}), 403
        else:
            ## In case method sent was not alllowed.
            return jsonify({"status": "Error", "code": 405, "reason": "Method Not Allowed"}), 405
    except Exception as e: 
        ## In case of error.
        return jsonify({"status":"Error", "code": 500, "reason": str(e)}), 500

## user service
@app.route('/user', methods=['POST','PUT','GET','DELETE'])
def user():
    try:
        ## Method: POST /user
        if request.method == 'POST':
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                ## for the use case where we should allow all request to create a new user.
                _auth = True ##validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = True
            if _auth:
                ## Validate required values, first creating a list of all required
                req_fields = ['activate', 'username', 'bday', 'pass', 'fname', 'phone', 'pin', 'plan', 'postalCode', 'terms', 'type', 'tenant']
                ## go and iterate to find all of them, if not _go will be false
                _go = True
                _go_validation = True
                for req_value in req_fields:
                    if req_value not in request.json:
                        _go = False
                    ## validate pass includes all required validations
                    if req_value == 'pass' and Helpers.validatePassword(request.json[req_value], pattern) == False:
                        _go_validation = False
                        if logging: print( "(!) Password Validation invalid ")
                ## if go, start the sign up flow, else 400 code to indicate a bad request.
                if _go and _go_validation:
                    ## Get email from request.json
                    s_email = request.json['email']
                    ## Query email to see if the user is yet created.
                    user = users_ref.document(s_email).get()
                    user = user.to_dict()
                    ## if user == None means user is not yet created, so flow continues, else return 409 indicating email already registered.
                    if user == None:
                        ## get pass from payload and decode 64 and then encrypt
                        _user_post_params = ['activate','username','bday','email','fname','phone','pin','plan','postalCode','terms','type', 'tenant']
                        _pcode = request.json['pass']
                        _pwrd = encrypt(Helpers.b64Decode(_pcode))
                        _pcode = ""
                        ## Create object to create the new user.
                        _objpay = {}
                        for _x in _user_post_params:
                            _objpay[_x] = request.json[_x]
                        _objpay['pass'] = _pwrd
                        ## send new user to be created, if created return 202 code and trxId code, else return 500 error while creating
                        if users_ref.document(s_email).set(_objpay):
                            ## If true means the user were created successfully. Return the trx code.
                            return jsonify({"trxId": transactionPost(s_email, False, 1, "User Post")}), 202
                        else:
                            ## The user wasnt created and the service returned a error.
                            return jsonify({"status": "Error", "code": 500, "reason": "Error while creating user. "}), 500
                    else:
                        ## The user already exists. Email already registered.
                        return jsonify({"status": "Error", "code": 409, "reason": "Email already registered" }), 409
                else: 
                    ## There are missing required fields.
                    return jsonify({"status": "Error", "code": 403, "reason": "Missing required fields or Validation Error"}), 403
            else: 
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Missing authorization"}), 401
        ## Method: PUT /user
        elif request.method == 'PUT': 
            ## Validate if the headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## If headers present, call to validateSession to know if it is a valid authorization,
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                _auth = False
            if _auth:
                ## validate minimum characters.
                if 'email' in request.json:
                    ## get reference for user to update
                    _user_to_update = users_ref.document(request.json['email'])
                    ## Create json template for the payload
                    _json_template = '{ }'
                    ## Load the json payload 
                    _json_payload = json.loads(_json_template)
                    ## Set an array with all required fields.
                    req_fields = ['activate', 'username', 'bday', 'fname', 'phone', 'pin', 'plan', 'postalCode', 'type', 'tenant']
                    ## define a flag to send or not the request.
                    _go = False
                    ## Create a for loop addressing all the required fields
                    for req_value in req_fields:
                        ## In case required field in json payload 
                        if req_value in request.json:
                            ## update _json_payload object adding current field.
                            _json_payload.update({req_value: request.json[req_value]})
                            ## update flag to update user
                            _go = True
                    ## in case the user wants to update the password.
                    if 'pass' in request.json:
                        ## decoding base 64 pass.
                        _encoded_pass = Helpers.b64Decode(request.json['pass'])
                        ## Encryting pass
                        _encoded_pass = encrypt(_encoded_pass)
                        ## Appending to the payoad
                        _json_payload.update({"pass": _encoded_pass})
                        ## updating flag
                        _go = True
                    ## If _go == True send request, else send error message
                    if _go:
                        try:
                            ## the user is updated with the request just generated.
                            _response = _user_to_update.update(_json_payload)
                        except Exception as e:
                            ## In case of an error updating the user, retrieve a error message.
                            print('(!) >> Handled external service exception: ' + str(e) )
                            return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "User cannot be updated."}), 500
                        ## Generate a transaction record.
                        _trxId = transactionPost(request.json['email'], False, 1, "User Put")
                        ## In case all went smooth, return a successful message.
                        return jsonify({"status": "success", "code": "202", "reason": "User information updated successfully.", "trxId": _trxId}), 202
                    else: 
                        return jsonify({"status": "Error", "code": "400", "reason": "Send at least one field to be updated."}), 400
                else:
                    return jsonify({"status": "Error", "code": "400", "reason": "Review request payload"}), 400
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## Method: GET /user
        elif request.method == 'GET': 
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## list all the values to be returned in the get object.
                _user_fields = ['activate','username','bday','email','fname','phone','plan','postalCode','terms','type','tenant','pin'] 
                ### Set the base for the json block to be returned. Define the data index for the list of users
                _json_data_block = {"items": []}
                ## If query filter present in url params it will save it, else will set False.
                _query = False if 'filter' not in request.args else request.args.get('filter')
                ## If id filter present in url params it will save it, else will set false.
                _id = False if 'id' not in request.args else request.args.get('id')
                ## set default value for limit and count. 
                _limit =  10 
                _count = 0
                _username = False
                _active = "N"
                ## Validate if _query present
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if limit param present set the limit value
                    _limit = int(_parameters['limit']) if 'limit' in _parameters else _limit
                    ## if username param present, set the username param
                    _username = str(_parameters['username']) if 'username' in _parameters else _username
                    ## if active param present validates the str value, if true seet True, else set False. if not present, 
                    ## sets _active to "N" to ignore the value
                    if 'active' in _parameters:
                        _active = True if str(_parameters['active']).lower() == 'true' else _active
                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = users_ref.where(filter=FieldFilter("email", "==", _id))
                elif _username:
                    ## The case username is present, will search with the specific username. 
                    _search = users_ref.where(filter=FieldFilter("username", "==", _username))
                    if _active != "N":
                        ## In case the _active param is present in valid fashion, will search for active or inactiv
                        ## e users.
                        _search = _search.where(filter=FieldFilter("activate", "==", _active))
                elif _active != "N":
                    ## In case activate is present, will search for active or inactive users.
                    _search = users_ref.where(filter=FieldFilter("activate", "==", _active))
                else:
                    ## In case any param was present, will search all
                    _search = users_ref
                ## Loop in all the users inside the users_ref object
                for _us in _search.stream():
                    ## set the temporal json_blocl
                    _json_block_l = {}
                    ## apply the to_dict() to the current user to use their information.
                    _acc = _us.to_dict()
                    ## Add a +1 to the count
                    _count += 1
                    ## Iterates into the _user_fields object to generate the json object for that user.
                    for _x in _user_fields:
                        ## Generates the json object.
                        _json_block_l[_x] = _acc[_x]
                    ## Each iteration, append the user block to the main payload.
                    _json_data_block["items"].append(_json_block_l)
                    if _count+1 > _limit: break
                ## Before return a response, adding parameters for the get.
                _json_data_block["limit"] = _limit
                _json_data_block["count"] = _count
                ## In case count > 0 it returns True, else False.
                _json_data_block["containsData"] = True if _count > 0 else False 
                _json_data_block["query"] = _query
                return jsonify(_json_data_block), 200
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## user Delete service
        elif request.method == 'DELETE':
            _errors = 0
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## Logic to get params ######################################################
                ## If query filter present in url params it will save it, else will set False.
                _query = False if 'filter' not in request.args else request.args.get('filter')
                ## If id filter present in url params it will save it, else will set false.
                _id = False if 'id' not in request.args else request.args.get('id')
                _username = False
                _active = "N"
                ## Logic to set query ######################################################
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if username param present, set the username param
                    _username = str(_parameters['username']) if 'username' in _parameters else _username
                    ## if active param present validates the str value, if true seet True, else set False. if not present, 
                    ## sets _active to "N" to ignore the value
                    if 'active' in _parameters:
                        _active = False if str(_parameters['active']).lower() == 'true' else False
                        
                ## Logic to get data
                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = users_ref.where(filter=FieldFilter("email", "==", _id))
                elif _username:
                    ## The case username is present, will search with the specific username. 
                    _search = users_ref.where(filter=FieldFilter("username", "==", _username))
                elif _active != "N":
                    ## In case activate is present, will search for active or inactive users.
                    _search = users_ref.where(filter=FieldFilter("activate", "==", _active))
                else:
                    ## In case any param was present, will search all
                    _search = users_ref.where(filter=FieldFilter("email", "==", ""))
                ## Loop in all the users inside the users_ref object
                _trx = {}
                for _us in _search.stream():
                    ## apply the to_dict() to the current user to use their information.
                    _acc = _us.to_dict()
                    ## validate if deletion was successful
                    if deleteUser(_acc['email'], _acc['username']):
                        ## Add the trx number to the user email to the return response
                        _trx[_acc['email']] = transactionPost(_auth['userId'], False, 2, "User Delete")
                    else:
                        ## Sums error count
                        _errors += 1
                ## validated the numer of errors
                if _errors == 0:
                    ## if no errors returns only the trx 
                    return jsonify(_trx), 200
                else:
                    ## if errors, returns the error count and the trx successful
                    return jsonify({"status": "Error", "code": 500, "reason": "There was errors while deletingn", "errorCount": _errors, "transactions": [_trx]}), 401
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
    except Exception as e:
        print (e)
        return jsonify({"status":"Error", "code": 500, "reason": str(e)}), 500

## Workspace service.
@app.route('/workspace', methods=['POST','PUT','GET','DELETE'])
def workspace():
    try:
        ## Method: POST /workspace
        if request.method == 'POST':
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## Look for the workspace to exist.
                if 'TaxId' in request.json:
                    ## Search for a wsp with that TaxId
                    _wsp_exist = wsp_ref.document(request.json['TaxId']).get()
                    ## format the json object
                    _wsp_exist = _wsp_exist.to_dict()
                ## If the wsp with that taxId do not exists proceeeds, otherwise return a 403 http code.
                if _wsp_exist == None:
                    ## Validate required values, first creating a list of all required
                    req_fields = ['Owner', 'TaxId', 'LegalName', 'InformalName', 'ShortCode', 'CountryCode', 'State', 'City', 'AddressLine1', 'AddressLine2', 'AddressLine3', 'AddressLine4', 'PhoneCountryCode', 'PhoneNumber', 'Email', 'MainHexColor', 'AlterHexColor', 'LowHexColor', 'Level', 'CreationDate', 'PostalCode']
                    ## go and iterate to find all of them, if not _go will be false
                    _go = True
                    ## For Loop going for all the required fields.
                    for req_value in req_fields:
                        ## if it is not in the parameters, set flag to false.
                        if req_value not in request.json:
                            _go = False
                    if _go:
                        ## Create json template for the payload
                        _json_template = '{ }'
                        ## Load the json payload 
                        _json_payload = json.loads(_json_template)
                        ## Create a for loop addressing all the required fields
                        for req_value in req_fields:
                            ## update _json_payload object adding current field.
                            _json_payload.update({req_value: request.json[req_value]})
                        _json_payload.update({"Active": True})
                        # create workspace.
                        try:
                            ## Call to create the workspace.
                            wsp_ref.document(request.json['TaxId']).set(_json_payload)
                        except Exception as e:
                            ## In case of an error updating the user, retrieve a error message.
                            print('(!) >> Handled external service exception: ' + str(e) )
                            return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "User cannot be updated."}), int(str(e)[0:3])
                        ## in case the ws is created, returns 200 abd the trxId 
                        return jsonify({"status": "success", "code": 200, "reason": "Workspace created succesfully.", "trxId": transactionPost(request.json['Owner'],False, 1, "Workspace POST")}), 200
                    else:
                        ## in case any required field is not present, will return a 400
                        return jsonify({"status": "Error", "code": 400, "reason": "Missing required fields"}), 400
                else: 
                    ## In case ws TaxId is already registered, will trwo a 403 error.
                    return jsonify({"status": "Error", "code": 403, "reason": "Workspace TaxId already registered."}), 403
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## Method: PUT /workspace
        elif request.method == 'PUT':
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## Look for the workspace to exist.
                if 'TaxId' in request.json and 'Owner' in request.json:
                    ## Search for a wsp with that TaxId
                    _wsp_exist = wsp_ref.document(request.json['TaxId'])
                    ## format the json object to get values from it
                    _fs_user = _wsp_exist.get().to_dict()
                    ## continue if a workspace with the taxId send already exist and the owner match.
                    if _wsp_exist != None and _fs_user['Owner'] == request.json['Owner']:
                        ## Creation of the optional fields that could be sent to update the workspace.
                        _opt_fields = ['LegalName','InformalName','ShortCode','CountryCode','State','City','AddressLine1','AddressLine2','AddressLine3','AddressLine4','PhoneCountryCode','PhoneNumber','Email','MainHexColor','AlterHexColor','LowHexcolor','Active']
                        ## define a flag to send or not the request.
                        _go = False
                        ## Create json template for the payload
                        _json_template = '{ }'
                        ## Load the json payload 
                        _json_payload = json.loads(_json_template)
                        ## Create a for loop addressing all the required fields
                        for req_value in _opt_fields:
                            ## In case required field in json payload 
                            if req_value in request.json:
                                ## update _json_payload object adding current field.
                                _json_payload.update({req_value: request.json[req_value]})
                                ## update flag to update user
                                _go = True
                        if _go:
                            try:
                                ## Call to create the workspace.
                                _response = _wsp_exist.update(_json_payload)
                            except Exception as e:
                                ## In case of an error updating the user, retrieve a error message.
                                print('(!) >> Handled external service exception: ' + str(e) )
                                return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "User cannot be updated."}), int(str(e)[0:3])
                            ## in case the ws is created, returns 200 abd the trxId 
                            return jsonify({"status": "success", "code": 202, "reason": "Workspace updated succesfully.", "trxId": transactionPost(request.json['Owner'], False, 1, "Workspace Put")}), 202
                        else:
                            ## in case any required field is not present, will return a 400
                            return jsonify({"status": "Error", "code": 400, "reason": "No fields to be updated, review the request."}), 400
                    else:
                        ## In case ws TaxId is already registered, will trwo a 403 error.
                        return jsonify({"status": "Error", "code": 403, "reason": "Workspace not found or Owner user does not match. Review the payload and try again."}), 403
                else:
                    ## in case any required field is not present, will return a 400
                    return jsonify({"status": "Error", "code": 400, "reason": "Review request payload"}), 400
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## Method: GET /workspace
        elif request.method == 'GET': 
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## list all the values to be returned in the get object.
                _ws_fields = ['Owner', 'TaxId', 'LegalName', 'InformalName', 'ShortCode', 'CountryCode', 'State', 'City', 'AddressLine1', 'AddressLine2', 'AddressLine3', 'AddressLine4', 'PhoneCountryCode', 'PhoneNumber', 'Email', 'MainHexColor', 'AlterHexColor', 'LowHexColor', 'Level', 'Active', 'CreationDate', 'PostalCode']
                ### Set the base for the json block to be returned. Define the data index for the list of users
                _json_data_block = {"items": []}
                ## If query filter present in url params it will save it, else will set False.
                _query = False if 'filter' not in request.args else request.args.get('filter')
                ## If id filter present in url params it will save it, else will set false.
                _id = False if 'id' not in request.args else request.args.get('id')
                ## set default value for limit and count. 
                _limit =  10 
                _count = 0
                _owner = False
                _shortCode = False
                _active = "N"

                ## Validate if _query present
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if limit param present set the limit value
                    _limit = int(_parameters['limit']) if 'limit' in _parameters else _limit
                    ## if username param present, set the owner param
                    _owner = str(_parameters['owner']) if 'owner' in _parameters else _owner
                    ## if shortCode param present, set the shortCode param
                    _shortCode = str(_parameters['shortCode']) if 'shortCode' in _parameters else _shortCode
                    ## if active param present validates the str value, if true seet True, else set False. if not present, 
                    ## sets _active to "N" to ignore the value
                    if 'active' in _parameters:
                        _active = True if str(_parameters['active']).lower() == 'true' else False
                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = wsp_ref.where(filter=FieldFilter("TaxId", "==", _id))
                elif _shortCode: 
                    ## the case of shortCode is present wull search for it.
                    _search = wsp_ref.where(filter=FieldFilter("ShortCode", "==", _shortCode))
                elif _owner:
                    ## The case username is present, will search with the specific username. 
                    _search = wsp_ref.where(filter=FieldFilter("Owner", "==", _owner))
                    if _active != "N":
                        ## In case the _active param is present in valid fashion, will search for active or inactiv
                        ## e users.
                        _search = _search.where(filter=FieldFilter("Active", "==", _active))
                elif _active != "N":
                    ## In case activate is present, will search for active or inactive users.
                    _search = wsp_ref.where(filter=FieldFilter("Active", "==", _active))
                else:
                    ## In case any param was present, will search all
                    _search = wsp_ref
                ## Loop in all the users inside the users_ref object
                for _ws in _search.stream():
                    ## set the temporal json_blocl
                    _json_block_l = {}
                    ## apply the to_dict() to the current user to use their information.
                    _acc = _ws.to_dict()
                    ## Add a +1 to the count
                    _count += 1
                    ## Iterates into the _user_fields object to generate the json object for that user.
                    for _x in _ws_fields:
                        ## Generates the json object.
                        _json_block_l[_x] = _acc[_x]
                    ## Each iteration, append the user block to the main payload.
                    _json_data_block["items"].append(_json_block_l)
                    if _count+1 > _limit: break
                ## Before return a response, adding parameters for the get.
                _json_data_block["limit"] = _limit
                _json_data_block["count"] = _count
                ## In case count > 0 it returns True, else False.
                _json_data_block["containsData"] = True if _count > 0 else False 
                _json_data_block["query"] = _query
                return jsonify(_json_data_block), 200
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## Method: DELETE /workspace
        elif request.method == 'DELETE':
            _errors = 0
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## Logic to get params ######################################################
                ## If query filter present in url params it will save it, else will set False.
                _query = False if 'filter' not in request.args else request.args.get('filter')
                ## If id filter present in url params it will save it, else will set false.
                _id = False if 'id' not in request.args else request.args.get('id')
                _owner = False
                _shortCode = False
                _active = "N"

                ## Validate if _query present
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if username param present, set the owner param
                    _owner = str(_parameters['owner']) if 'owner' in _parameters else _owner
                    ## if shortCode param present, set the shortCode param
                    _shortCode = str(_parameters['shortCode']) if 'shortCode' in _parameters else _shortCode
                    ## if active param present validates the str value, if true seet True, else set False. if not present, 
                    ## sets _active to "N" to ignore the value
                    if 'active' in _parameters:
                        _active = True if str(_parameters['active']).lower() == 'true' else False
                        
                ## Logic to get data
                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = wsp_ref.where(filter=FieldFilter("TaxId", "==", _id))
                elif _shortCode: 
                    ## the case of shortCode is present wull search for it.
                    _search = wsp_ref.where(filter=FieldFilter("ShortCode", "==", _shortCode))
                    if _active != "N":
                        ## In case the _active param is present in valid fashion, will search for active or inactiv
                        ## e users.
                        _search = _search.where(filter=FieldFilter("Active", "==", _active))
                elif _owner:
                    ## The case username is present, will search with the specific username. 
                    _search = wsp_ref.where(filter=FieldFilter("Owner", "==", _owner))
                    if _active != "N":
                        ## In case the _active param is present in valid fashion, will search for active or inactiv
                        ## e users.
                        _search = _search.where(filter=FieldFilter("Active", "==", _active))
                else:
                    ## In case any param was present, will search all
                    _search = wsp_ref.where(filter=FieldFilter("TaxId", "==", ""))

                ## Loop in all the users inside the users_ref object
                _trx = {}
                for _us in _search.stream():
                    ## apply the to_dict() to the current user to use their information.
                    _acc = _us.to_dict()
                    ## validate if deletion was successful
                    if deleteWorkspace(_acc['TaxId']):
                        ## Add the trx number to the user email to the return response
                        _trx[_acc['TaxId']] = transactionPost(_auth['userId'], False, 2, "Workspace Delete")
                    else:
                        ## Sums error count
                        _errors += 1
                ## validated the numer of errors
                if _errors == 0:
                    ## if no errors returns only the trx 
                    return jsonify(_trx), 200
                else:
                    ## if errors, returns the error count and the trx successful
                    return jsonify({"status": "Error", "code": 500, "reason": "There was errors while deleting", "errorCount": _errors, "transactions": [_trx]}), 401
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
    except Exception as e:
        print (e)
        ## in case of error prints the exception and the code.
        return jsonify({"status":"Error", "code": 500, "reason": str(e)}), 500
    
## Transactions service.
@app.route('/transaction', methods=['GET','DELETE'])
def transaction():
    try:
        ## Method: GET /transaction
        if request.method == 'GET':
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## list all the values to be returned in the get object.
                _trx_fields = ['dateTime','id','userId','alert','action','severity'] 
                ### Set the base for the json block to be returned. Define the data index for the list of trxs
                _json_data_block = {"items": []}
                ## Define _limit, _count, containsData and query
                ## If query filter present in url params it will save it, else will set False.
                _query = False if 'filter' not in request.args else request.args.get('filter')
                ## If id filter present in url params it will save it, else will set false.
                _id = False if 'id' not in request.args else request.args.get('id')
                ## set default value for limit and count. 
                _limit =  10 
                _count = 0
                _action = False
                _alert = "N"
                _userId = False
                ## Validate if _query present
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if limit param present set the limit value
                    _limit = int(_parameters['limit']) if 'limit' in _parameters else _limit
                    ## if action param present, set the action param
                    _action = str(_parameters['action']) if 'action' in _parameters else _action
                    ## if userId param present, set the userId param
                    _userId = str(_parameters['userId']) if 'userId' in _parameters else _userId
                    if 'alert' in _parameters:
                        _alert = True if str(_parameters['alert']).lower() == 'true' else False

                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = trx_ref.where(filter=FieldFilter("id", "==", _id))
                elif _action: 
                    ## the case of shortCode is present wull search for it.
                    _search = trx_ref.where(filter=FieldFilter("action", "==", _action))
                elif _alert != "N":
                    ## The case username is present, will search with the specific username. 
                    _search = trx_ref.where(filter=FieldFilter("alert", "==", _alert))
                elif _userId:
                    ## In case activate is present, will search for active or inactive users.
                    _search = trx_ref.where(filter=FieldFilter("userId", "==", _userId))
                else:
                    ## In case any param was present, will search all
                    _search = trx_ref
                ## Loop in all the trxs inside the trx_ref object
                for _trx in _search.stream():
                    ## set the temporal json_blocl
                    _json_block_l = {}
                    ## apply the to_dict() to the current trx to use their information.
                    _acc = _trx.to_dict()
                    ## Add a +1 to the count
                    _count += 1
                    ## Iterates into the _trx_fields object to generate the json object for that user.
                    for _x in _trx_fields:
                        ## Generates the json object.
                        _json_block_l[_x] = _acc[_x]
                    ## Each iteration, append the trx block to the main payload.
                    _json_data_block["items"].append(_json_block_l)
                    if _count+1 > _limit: break
                ## Before return a response, adding parameters for the get.
                _json_data_block["limit"] = _limit
                _json_data_block["count"] = _count
                ## In case count > 0 it returns True, else False.
                _json_data_block["containsData"] = True if _count > 0 else False 
                _json_data_block["query"] = _query
                return jsonify(_json_data_block), 200
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## Method: DELETE /workspace
        elif request.method == 'DELETE':
            _errors = 0
            ## Validate the required authentication headers are present
            if request.headers.get('SessionId') and request.headers.get('TokenId'):
                ## In case are present, call validate session. True if valid, else not valid. Fixed to true
                _auth = validateSession(request.headers.get('SessionId'), request.headers.get('TokenId'))
                ## If validateSession return false, delete the session id.
                if _auth == False: deleteSession(request.headers.get('SessionId'))
            else: 
                ## Fixed to true to allow outside calls to log in to the system,
                _auth = False
            if _auth:
                ## Logic to get params ######################################################
                ## If query filter present in url params it will save it, else will set False.
                _query = False if 'filter' not in request.args else request.args.get('filter')
                ## If id filter present in url params it will save it, else will set false.
                _id = False if 'id' not in request.args else request.args.get('id')
                ## set default value for limit and count. 
                _limit =  10 
                _count = 0
                _action = False
                _alert = "N"
                _userId = False
                ## Validate if _query present
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if limit param present set the limit value
                    _limit = int(_parameters['limit']) if 'limit' in _parameters else _limit
                    ## if username param present, set the owner param
                    _action = str(_parameters['action']) if 'action' in _parameters else _action
                    ## if shortCode param present, set the shortCode param
                    _userId = str(_parameters['userId']) if 'userId' in _parameters else _userId
                    if 'alert' in _parameters:
                        _alert = True if str(_parameters['alert']).lower() == 'true' else False

                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = trx_ref.where(filter=FieldFilter("id", "==", _id))
                elif _action: 
                    ## the case of shortCode is present wull search for it.
                    _search = trx_ref.where(filter=FieldFilter("action", "==", _action))
                elif _alert != "N":
                    ## The case username is present, will search with the specific username. 
                    _search = trx_ref.where(filter=FieldFilter("alert", "==", _alert))
                elif _userId:
                    ## In case activate is present, will search for active or inactive users.
                    _search = trx_ref.where(filter=FieldFilter("userId", "==", _userId))
                else:
                    ## In case any param was present, will search all
                    _search = trx_ref

                ## Loop in all the users inside the users_ref object
                _trx = {}
                for _us in _search.stream():
                    ## apply the to_dict() to the current user to use their information.
                    _acc = _us.to_dict()
                    ## validate if deletion was successful
                    if transactionDelete(_acc['id']):
                        ## Add the trx number to the user email to the return response
                        _trx[_acc['id']] = transactionPost(_auth['userId'], False, 3, "Transaction Delete")
                    else:
                        ## Sums error count
                        _errors += 1
                ## validated the numer of errors
                if _errors == 0:
                    ## if no errors returns only the trx 
                    return jsonify(_trx), 200
                else:
                    ## if errors, returns the error count and the trx successful
                    return jsonify({"status": "Error", "code": 500, "reason": "There was errors while deleting", "errorCount": _errors, "transactions": [_trx]}), 401
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
    except Exception as e:
        return jsonify({"status": "Error", "code": str(e)[0:3], "reason": str(e)}), 500

## API Status
@app.route('/')
def status():
    return "<p>App Status: <markup style='color:green'>Running fine</markup></p>"

## Encode token.
@app.route('/encode', methods=['GET'])
def encode():
    try:
        if request.args.get('_string'):
            _b64 = Helpers.b64Encode(request.args.get('_string'))
            _dec = Helpers.b64Decode(_b64)
            return jsonify({"status": "success", "original": _dec, "encoded": _b64}), 200
        else:
            return jsonify({"status", "error"}), 400
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

######################################################################
### Private Services  ################################################
######################################################################

## user DELETE Service
## user (DELETE)
## _id: (required) id of the user to be deleted
## _un: (optional) username of the user to delete
def deleteUser(_id, _un):
    try:
        print(" >> deleteUser() helper.")
        deleteUserTokens(_id)
        deleteUserTrx(_id)
        if users_ref.document(_id).delete():
            return True
        else: 
            return False
    except Exception as e:
        print ( "(!) Exception in function: deleteUser() ")
        print (e)
        return False

## workspace DELETE Service
## workspace (DELETE)
## _id: (required) id of the workspace to be deleted
def deleteWorkspace(_id):
    try:
        print(" >> deleteWorkspace() helper.")
        if wsp_ref.document(_id).delete():
            return True
        else: 
            return False
    except Exception as e:
        print ( "(!) Exception in function: deleteWorkspace() ")
        print (e)
        return False

## Auth POST Service
## auth (POST)
## _user: User Email for the Token authorization.
## _ilimited: If true will set a timedelta of 180 days, else will be only for 72 hours.
def authPost(_user, _ilimited):
    try:
        print(" >> authPost() service.")
        ## import datetime library
        from datetime import datetime, timedelta
        ## get current time
        current_date_time = datetime.now()
        ## generates string for the token
        token = Helpers.idGenerator(10)
        ## validates if _limited param present
        if _ilimited:
            ## if ilimited set token expiracy for 180days
            new_date_time = current_date_time + timedelta(days=180)
        else:
            ## if ilimited token not present, expiracy set for 3 days
            new_date_time = current_date_time + timedelta(hours=72)
        ## get current date time format.
        new_date_time = new_date_time.strftime("%d%m%YH%M%S")
        ## generate the json to create the token in firestore
        tobj = {
            "id" : token,
            "expire" : new_date_time,
            "username": _user
        }
        ## sends token to be created in firestore, if success returns token info, else prints error and returns False
        if tokens_ref.document(token).set(tobj):
            return tobj
        else: 
            _status =  {"status": "Error", "errorStatus": "An error ocurred while creating the token, try again."}
            print(_status)
            return False
    except Exception as e:
        print ( "(!) Exception in function: authPost() ")
        print (e)
        return False
    
## Auth GET Service
## auth (GET)
## _user: User Email for the Token authorization.
def authGet(_user):
    try:
        print(" >> authGet() service.")
        ## search in firestore from tokens of currrent user
        _tokens = tokens_ref.where(filter=FieldFilter("username", "==", _user))
        ## Set the tokens count to know how many tokens were processed.
        _tokens_count = 0
        ## Iterate the posible tokens for the user.
        for _tok in _tokens.stream():
            ## Save the current token object in _token
            _token = _tok
            ## sums 1 to the tokens count
            _tokens_count += 1
            ## Validate if the token is valid
            _valid = tokenValidator(_user, _token.id)
            ## In case _valid == False or tokens_count > 1 it will delete the token and return false indicating error. 
            if not _valid or _tokens_count > 1:
                authDelete(_tok.id)
                return False
        ## If tokens count == 1 we return the id value of the token.
        if _tokens_count > 0:
            ## returns token to dictionary
            return _token.to_dict()
        else:
            ## Else we return false indicating error.
            return False
    except Exception as e:
        print ( "(!) Exception in function: authGet() ")
        print (e)
        return False
    
## Auth DELETE Service
## auth (DELETE)
## _id: Token id to be deleted.
def authDelete(_id):
    try:
        print(" >> authDelete() service.")
        ## Delete sessions related to token
        _sessions = sess_ref.where(filter=FieldFilter("tokenId", "==", _id))
        for _ses in _sessions.stream():
            deleteSession(_ses.id)
        if tokens_ref.document(_id).delete():
            return True
        else: 
            return False
    except Exception as e:
        print ( "(!) Exception in function: authDelete() ")
        print (e)
        return False


## auth VALIDATION Service (legacy)
## auth (Validation)
## _user: username of the token
## _token: token id that wants to valdiate
def tokenValidator(_user, _token):
    try:
        print(" >> tokenValidator() helper.")
        from datetime import datetime
        current_date_time = datetime.now()
        current_date_time = current_date_time.strftime("%d%m%YH%M%S")
        new_current_date_time = datetime.strptime(current_date_time, '%d%m%YH%M%S')
        vauth = tokens_ref.document(_token).get()
        if vauth != None:
            try:
                objauth = vauth.to_dict()
                expire_date = objauth['expire']
                new_expire_date = datetime.strptime(expire_date, '%d%m%YH%M%S')
                if new_current_date_time.date() < new_expire_date.date():
                    return True
                else: 
                    authDelete(_token)
                    return False
            except Exception as e:
                return {"status": "error"}      
        else:
            return jsonify({"status": "invalid token"})
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## auth DELETE ALL USER TOKENS Service (legacy)
## auth (DELETE ALL USER TOKENS)
## _un: (required) Username that want to delete all tokens of.
def deleteUserTokens(_un):
    print(" >> deleteUserTokens() helper.")
    ## search in firestore from tokens of currrent user
    _tokens = tokens_ref.where(filter=FieldFilter("username", "==", _un))
    ## Set the tokens count to know how many tokens were deleted.
    _tokens_count = 0
    ## for each token returned
    for _tok in _tokens.stream():
        ## if inside, _exists = true and delete current token
        _exists = True
        authDelete(_tok.id)
        _tokens_count += 1
    return _tokens_count    

## session DELETE Service
## session (DELETE)
## _id: (required) id of the session object want to delete.
def deleteSession(_id):
    try:
        print(" >> deleteSession() helper.")
        if sess_ref.document(_id).delete():
            return True
        else: 
            return False
    except Exception as e:
        print ( "(!) Exception in function: deleteSession() ")
        print (e)
        return False

## session VALIDATE Service
## session (VALIDATE)
## _id: (required) id of the session object want to validate.
## _token: (required) token id vant to match.
def validateSession(_id, _tokenid):
    try:
        print(" >> validateSession() helper.")
        _sess = sess_ref.document(_id).get()        
        if _sess != None:
            _dicted = _sess.to_dict()
            if _dicted['tokenId'] == _tokenid:
                return _dicted
            else:
                return False
        else:
            return False
    except Exception as e:
        print ( "(!) Exception in function: validateSession() ")
        print (e)
        return False


## Transaction POST (not public) Service
## Transaction Number Generator (legacy)
## _userId: For the user id that will be linked to the trx
## _alert: if it is necesary to generate an alert for this transaction action.
## _severity: It is the severity of the action. 0 less severe, 5 maximum severity.
## _action: The name of the action that is generated the transaction for.
def transactionPost(_userId, _alert, _severity, _action):
    try:
        print(" >> transactionPost() helper.")
        from datetime import datetime
        _now = datetime.now()
        _dateGen = _now.strftime("%d%m%YH%M%S")
        _trxId = Helpers.randomString(4) + _dateGen + Helpers.randomString(20)
        _trx_obj = {
            "dateTime" : _dateGen,
            "userId" : _userId,
            "id": _trxId,
            "alert": _alert if _alert else False,
            "severity": _severity if _severity else 0,
            "action": _action if _action else "Unclassified"
        }
        if trx_ref.document(_trxId).set(_trx_obj):
            return _trxId
        else: 
            return False
    except Exception as e:
        print ( "(!) Exception in function: transactionPost() ")
        print (e)
        return False
    
## Transaction DELETE Service
## Transaction Number deletor function
## _transaction_id: Number of the transaction.
def transactionDelete(_transaction_id):
    try:
        print(" >> deleteTransaction() helper.")
        if trx_ref.document(_transaction_id).delete():
            return True
        else: 
            return False
    except Exception as e:
        print ( "(!) Exception in function: deleteTransaction() ")
        print (e)
        return False

## Transaction DELETE all user Transactions
## Transaction Number deletor function
## _transaction_id: Number of the transaction.
def deleteUserTrx(_userId):
    try:
        print(" >> deleteUserTrx() helper.")
        ## search in firestore from tokens of currrent user
        _trx = trx_ref.where(filter=FieldFilter("userId", "==", _userId))
        ## Set the tokens count to know how many tokens were deleted.
        _trx_count = 0
        ## for each token returned
        for _trx in _trx.stream():
            ## if inside, _exists = true and delete current token
            transactionDelete(_trx['id'])
            _trx_count +=1
        return _trx_count   
    except Exception as e:
        print ( "(!) Exception in function: deleteUserTrx() ")
        print (e)
        return False

########################################
### Helpers ############################
########################################

## Encrypt
def encrypt(_string):
    try:    
        print(" >> encrypt() helper.")
        bc_salt = app.config['CONF_SALT_KEY']
        salt = bc_salt.encode('utf-8')
        bytes_pwd = _string.encode('utf-8')
        hashed_pwd = bcrypt.hashpw(bytes_pwd, salt)
        return hashed_pwd
    except Exception as e:
        print ( "(!) Exception in function: encrypt() ")
        print (e)
        return False


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)