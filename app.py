## Flask API for adminde-tc project.
## Pylexandria Project.
## Coded by: Mauricio Alcala (@maualkla)
## Creation Date: May 2023.
## Current Version: 0.03
## Last Modification Date: Oct 2023.
## More info at @intmau in X.com or in http://py.maualkla.com
## Description: API for the services required by the adminde-tc proyect.

## Imports
from flask import Flask, jsonify, request
from firebase_admin import credentials, firestore, initialize_app
from google.cloud.firestore_v1.base_query import FieldFilter
from config import Config
import rsa, bcrypt, base64, json

## Initiate Public and private key
publicKey, privateKey = rsa.newkeys(512)

## Initialize Flask App
app = Flask(__name__)

## Setup env vars
app.config.from_object(Config)

## Initialize Firestone DB
cred = credentials.Certificate('key.json')
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
                _decoded_str = b64Decode(request.json['requestString'])
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
                        _idg = idGenerator(15)
                        ## Validate if the pass is the same in the request as it is in the firebase_object
                        if _requ == _fire:
                            ## Get the user token. In case exist it will retrieve the tokenId. Else return False.
                            _token = getToken(_sess_params[0])
                            ## Validate if valid token. is present. If not, generates a new token for the user.
                            if _token == False:  
                                ## calls tokenGenerator sending user name and False. To generate a temporal token.
                                _token = tokenGenerator(_sess_params[0], False)
                            ## Generate the json object required to create the session object.
                            _session_json = {
                                "clientIp" : _client['ip'],
                                "clientVersion": _client['browser'],
                                "id": _idg,
                                "tokenId": _token,
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
                            return jsonify({"_session_id": _idg, "trxId": trxGenerator(currentDate(), _sess_params[0])}), 200
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
        return {"status":"Error", "code": 500, "reason": str(e)}

## Login service (deprecated)
@app.route("/login", methods=['GET'])
def login():
    try:
        ### validate parameters
        if 'u' not in request.args or 'p' not in request.args:
            return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 400
        else: 
            ## save parameters into local vars, decode from b64 both password and user.
            _username = request.args.get('u')
            _username = b64Decode(_username)
            _pass = request.args.get('p')
            _pass = b64Decode(_pass)
            ## go to firestore and get user with l_user id
            user = users_ref.document(_username).get().to_dict()
            ## if user not found, user will = None and will send 404, else it will continue
            if user != None:
                ## encrypt and decode reqpass
                _requ = encrypt(_pass).decode('utf-8')
                _fire = user['pass'].decode('utf-8')
                ## validate if both pass are same and continue, else return 401
                if _requ == _fire:
                    ## define exist flag to false
                    _exists = False
                    ## delete all existing tokens for the current user.
                    deleteUserTokens(_username)
                    ## generates token with user, send False flag, to get a token valid for 72 hours, True for 180 days
                    _token = tokenGenerator(_username, False)
                    ## return _token generated before, a transaction id and a 200 code.
                    return jsonify({"expire": "", "id": _token, "username": "", "trxId": trxGenerator(currentDate(), _username), "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 200
                else:
                    return jsonify({"status": "Error", "code": "401", "reason": "Not Authorized, review user or password", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 401
            else:
                return jsonify({"status": "Error", "code": "404", "reason": "Not Authorized, review user or password", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 404
    except Exception as e: 
        return {"status":"Error", "code": "500", "reason": str(e), "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}

## Logout Service
@app.route('/logout', methods=['GET'])
def logout():
    try:
        ### validate parameters
        if '_id' not in request.args or '_username' not in request.args:
            ## Return error response, missing required fields
            return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 400
        else: 
            ## get and decode the request parameter
            _username = request.args.get('_username')
            _username = b64Decode(_username)
            ## Delete all user related tokens.
            _tokens = deleteUserTokens(_username)
            trxGenerator(currentDate(), _username)
            ## Return 440 logout http response code.
            if _tokens > 0:
                return jsonify({"status": "success", "code": "440", "reason": "session closed", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 440
            else:
                return jsonify({"status": "error", "code": "404", "reason": "User not logged.", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 404
    except Exception as e: 
        return {"status":"Error", "code": "500", "reason": str(e), "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}

## Sign up service
@app.route('/signup', methods=['POST'])
def signup():
    try:
        ## Validate required values, first creating a list of all required
        req_fields = ['username', 'bday', 'fname', 'pass', 'phone', 'pin', 'plan', 'postalCode', 'terms', 'type']
        ## go and iterate to find all of them, if not _go will be false
        _go = True
        for req_value in req_fields:
            if req_value not in request.json:
                _go = False

        ## if go, start the sign up flow, else 400 code to indicate a bad request.
        if _go:
            ## Get email from request.json
            s_email = request.json['email']
            ## Query email to see if the user is yet created.
            user = users_ref.document(s_email).get()
            user = user.to_dict()
            ## if user == None means user is not yet created, so flow continues, else return 409 indicating email already registered.
            if user == None:
                ## get pass from payload and decode 64 and then encrypt
                _pcode = request.json['pass']
                _pcode = b64Decode(_pcode)
                _pwrd = encrypt(_pcode)
                ## Create object to create the new user.
                objpay = {
                    "activate": True,
                    "username": request.json['username'],
                    "bday": request.json['bday'],
                    "email": request.json['email'],
                    "fname": request.json['fname'],
                    "pass": _pwrd,
                    "phone": request.json['phone'],
                    "pin": request.json['pin'],
                    "plan": request.json['plan'],
                    "postalCode": request.json['postalCode'],
                    "terms": request.json['terms'],
                    "type": request.json['type']
                }
                ## Get current date
                _tempdate = str(currentDate())
                ## send new user to be created, if created return 202 code and trxId code, else return 500 error while creating
                if users_ref.document(s_email).set(objpay):
                    return jsonify({"trxId": trxGenerator(_tempdate,s_email), "alert": "this service is deprecated and will be removed by v0.03 - Use the /user service instead."}), 202
                else:
                    return jsonify({"status": "Error while creating user. ", "alert": "this service is deprecated and will be removed by v0.03 - Use the /user service instead."}), 500
            else:
                return jsonify({"status": "Email already registered", "alert": "this service is deprecated and will be removed by v0.03 - Use the /user service instead." }), 409
        else: 
            return jsonify({"status": "Review request payload", "alert": "this service is deprecated and will be removed by v0.03 - Use the /user service instead."}), 400
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}
    
## user service
@app.route('/user', methods=['POST','PUT','GET'])
def user():
    try:
        ## Method: POST /user
        if request.method == 'POST':
            _auth = True if request.headers.get('SessionId') and request.headers.get('TokenId') else False
            if _auth:
                ## Validate required values, first creating a list of all required
                req_fields = ['activate', 'username', 'bday', 'pass', 'fname', 'phone', 'pin', 'plan', 'postalCode', 'terms', 'type', 'tenant']
                ## go and iterate to find all of them, if not _go will be false
                _go = True
                for req_value in req_fields:
                    if req_value not in request.json:
                        _go = False
                ## if go, start the sign up flow, else 400 code to indicate a bad request.
                if _go:
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
                        _pwrd = encrypt(b64Decode(_pcode))
                        _pcode = ""
                        ## Create object to create the new user.
                        _objpay = {}
                        for _x in _user_post_params:
                            _objpay[_x] = request.json[_x]
                        _objpay['pass'] = _pwrd
                        ## send new user to be created, if created return 202 code and trxId code, else return 500 error while creating
                        if users_ref.document(s_email).set(_objpay):
                            ## If true means the user were created successfully. Return the trx code.
                            return jsonify({"trxId": trxGenerator(str(currentDate()),s_email)}), 202
                        else:
                            ## The user wasnt created and the service returned a error.
                            return jsonify({"status": "Error", "code": 500, "reason": "Error while creating user. "}), 500
                    else:
                        ## The user already exists. Email already registered.
                        return jsonify({"status": "Error", "code": 409, "reason": "Email already registered" }), 409
                else: 
                    ## There are missing required fields.
                    return jsonify({"status": "Error", "code": 400, "reason": "Missing required fields"}), 400
            else: 
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Missing authorization"}), 401
        ## Method: PUT /user
        elif request.method == 'PUT': 
            ## validate minimum characters.
            if 'email' in request.json:
                ## get reference for user to update
                _user_to_update = users_ref.document(request.json['email'])
                ## Create json template for the payload
                _json_template = '{ }'
                ## Load the json payload 
                _json_payload = json.loads(_json_template)
                ## Set an array with all required fields.
                req_fields = ['activate', 'username', 'bday', 'fname', 'phone', 'pin', 'plan', 'postalCode', 'type']
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
                    _encoded_pass = b64Decode(request.json['pass'])
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
                    _trxId = trxGenerator(currentDate(), request.json['email'])
                    ## In case all went smooth, return a successful message.
                    return jsonify({"status": "success", "code": "202", "reason": "User information updated successfully.", "trxId": _trxId}), 202
                else: 
                    return jsonify({"status": "Error", "code": "400", "reason": "Send at least one field to be updated."}), 400
            else:
                return jsonify({"status": "Error", "code": "400", "reason": "Review request payload"}), 400
        ## Method: GET /user
        elif request.method == 'GET': 
            ## list all the values to be returned in the get object.
            _user_fields = ['activate','username','bday','email','fname','phone','plan','postalCode','terms','type'] 
            ### Set the base for the json block to be returned. Define the data index for the list of users
            _json_data_block = {"items": []}
            ## Define _limit, _count, containsData and query
            _query = ""
            _limit = 10 if 'limit' not in request.args else int(request.args.get('limit')) if int(request.args.get('limit')) < 1001 and int(request.args.get('limit')) > 0 else 10
            _containsData = False
            _count = 0
            ## Loop in all the users inside the users_ref object
            for _us in users_ref.stream():
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
            _json_data_block["query"] = ""
            return jsonify(_json_data_block), 200
    except Exception as e:
        print (e)
        return jsonify({"status":"Error", "code": "500", "reason": str(e)}), 500

## Workspace service.
@app.route('/workspace', methods=['POST','PUT'])
def workspace():
    try:
        ## Method: POST /workspace
        if request.method == 'POST':
            ## Look for the workspace to exist.
            if 'TaxId' in request.json:
                ## Search for a wsp with that TaxId
                _wsp_exist = wsp_ref.document(request.json['TaxId']).get()
                ## format the json object
                _wsp_exist = _wsp_exist.to_dict()
            ## If the wsp with that taxId do not exists proceeeds, otherwise return a 403 http code.
            if _wsp_exist == None:
                ## Validate required values, first creating a list of all required
                req_fields = ['Owner', 'TaxId', 'LegalName', 'InformalName', 'ShortCode', 'CountryCode', 'State', 'City', 'AddressLine1', 'AddressLine2', 'AddressLine3', 'AddressLine4', 'PhoneCountryCode', 'PhoneNumber', 'Email', 'MainHexColor', 'AlterHexColor', 'LowHexColor', 'Level', 'Active', 'CreationDate', 'PostalCode']
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
                    # create workspace.
                    try:
                        ## Call to create the workspace.
                        wsp_ref.document(request.json['TaxId']).set(_json_payload)
                    except Exception as e:
                        ## In case of an error updating the user, retrieve a error message.
                        print('(!) >> Handled external service exception: ' + str(e) )
                        return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "User cannot be updated."}), 500
                    return jsonify({"status": "success", "code": "200", "reason": "Workspace created succesfully.", "trxId": trxGenerator(currentDate(), request.json['Owner'])}), 200
                else:
                    return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields"}), 400
            else: 
                return jsonify({"status": "Error", "code": "403", "reason": "Workspace TaxId already registered."}), 403
        ## Method: PUT /workspace
        elif request.method == 'PUT':
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
                            return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "Error updating workspace."}), 500
                        return jsonify({"status": "success", "code": "202", "reason": "Workspace updated succesfully.", "trxId": trxGenerator(currentDate(), request.json['Owner'])}), 202
                    else:
                        return jsonify({"status": "Error", "code": "400", "reason": "No fields to be updated, review the request."}), 400
                else:
                    return jsonify({"status": "Error", "code": "403", "reason": "Workspace not found or Owner user does not match. Review the payload and try again."}), 403
            else:
                return jsonify({"status": "Error", "code": "400", "reason": "Review request payload"}), 400
    except Exception as e:
        return jsonify({"status": "Error", "code": str(e)[0:3], "reason": str(e)}), 500

## Transactions service.
@app.route('/transaction', methods=['GET'])
def transaction():
    try:
        ## list all the values to be returned in the get object.
        _trx_fields = ['date','id','user'] 
        ### Set the base for the json block to be returned. Define the data index for the list of trxs
        _json_data_block = {"items": []}
        ## Define _limit, _count, containsData and query
        _query = ""
        _limit = 10 if 'limit' not in request.args else int(request.args.get('limit')) if int(request.args.get('limit')) < 1001 and int(request.args.get('limit')) > 0 else 10
        _count = 0
        ## Loop in all the trxs inside the trx_ref object
        for _trx in trx_ref.stream():
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
    except Exception as e:
        return jsonify({"status": "Error", "code": str(e)[0:3], "reason": str(e)}), 500

## (deprecated) v0.01 Auth a token.
@app.route('/vauth', methods=['POST'])
def vauth():
    try:
        vauth = tokenValidator(request.json['username'], request.json['id'])
        if vauth:
            return jsonify({"status": "valid", "alert": "this service is deprecated and will be removed by v0.03 - Use the /auth service instead."}), 200
        else:
            return jsonify({"status": "not-valid", "alert": "this service is deprecated and will be removed by v0.03 - Use the /auth service instead."}), 200
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}
    
## Auth a token.
@app.route('/auth', methods=['POST'])
def auth():
    try:
        ## Validate if required fields are in the json request.
        if 'id' not in request.json or 'username' not in request.json:
            ## Return error response, missing required fields
            return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}), 400
        else: 
            ## go to tokenValidator and retrieve a valid or expired status.
            _auth = tokenValidator(request.json['username'], request.json['id'])
            if _auth:
                _response = {"status": "valid", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}
            else:
                _response = {"status": "error", "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}
            ## return the tokenvalidator status and a 200 code.
            return _response, 200
    except Exception as e:
        return {"status":"Error", "code": "500", "reason": str(e), "alert": "Warning, this Login service is deprecated and faces partial functionality. Please refer to the APIDOCS to see an alternative. This service will be deleted for the v0.05 of the product."}

## API Status
@app.route('/')
def status():
    return "<p>App Status: <markup style='color:green'>Running fine</markup></p>"

## Encode token.
@app.route('/encode', methods=['GET'])
def encode():
    try:
        if request.args.get('_string'):
            _b64 = b64Encode(request.args.get('_string'))
            _dec = b64Decode(_b64)
            return jsonify({"status": "success", "original": _dec, "encoded": _b64}), 200
        else:
            return jsonify({"status", "error"}), 400
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

########################################
### Private Services  ##################
########################################

## Token Services

## token generator (POST)
## _user: User Email for the Token.
## _ilimited: If true will set a timedelta of 180 days, else will be only for 72 hours.
def tokenGenerator(_user, _ilimited):
    try:
        print(" >> tokenGenerator() helper.")
        from datetime import datetime, timedelta
        current_date_time = datetime.now()
        token = idGenerator(10)
        if _ilimited:
            new_date_time = current_date_time + timedelta(days=180)
        else:
            new_date_time = current_date_time + timedelta(hours=72)
        new_date_time = new_date_time.strftime("%d%m%YH%M%S")
        tobj = {
            "id" : token,
            "expire" : new_date_time,
            "username": _user
        }
        if tokens_ref.document(token).set(tobj):
            return token
        else: 
            return {"status": "Error", "errorStatus": "An error ocurred while creating the token, try again."}
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## Token validation
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
                    deleteToken(_token)
                    return False
            except Exception as e:
                return {"status": "error"}      
        else:
            return jsonify({"status": "invalid token"})
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## Delete all user tokens.
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
        deleteToken(_tok.id)
        _tokens_count += 1
    return _tokens_count

## Get UserToken
def getToken(_un):
    try:
        print(" >> getToken() helper.")
        ## search in firestore from tokens of currrent user
        _tokens = tokens_ref.where(filter=FieldFilter("username", "==", _un))
        ## Set the tokens count to know how many tokens were processed.
        _tokens_count = 0
        ## Iterate the posible tokens for the user.
        for _tok in _tokens.stream():
            ## Save the current token object in _token
            _token = _tok
            ## sums 1 to the tokens count
            _tokens_count += 1
            ## Validate if the token is valid
            _valid = tokenValidator(_un, _token.id)
            ## In case _valid == False or tokens_count > 1 it will delete the token and return false indicating error. 
            if not _valid or _tokens_count > 1:
                deleteToken(_tok.id)
                return False
        ## If tokens count == 1 we return the id value of the token.
        if _tokens_count > 0:
            return _tok.id
        else:
            ## Else we return false indicating error.
            return False
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## Delete Token
def deleteToken(_id):
    try:
        print(" >> deleteToken() helper.")
        if tokens_ref.document(_id).delete():
            return True
        else: 
            return False
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}
    

## Session Services ####################
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
        return {"status": "An error Occurred", "error": str(e)}

########################################
### Helpers ############################
########################################

## return String (lenght)
def randomString(_length):
    try:
        print(" >> randomString() helper.")
        import random, string
        output_str = ''.join(random.choice(string.ascii_letters) for i in range(_length))
        return output_str
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## return userId
def idGenerator(_length):
    try:
        print(" >> idGenerator() helper.")
        userId = currentDate()
        userId = randomString(2) + userId + randomString(_length)
        return userId
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

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
        return {"status": "An error Occurred", "error": str(e)}

## Decrypt
def decrypt(_string):
    
    return False

## Transaction Number Generator
def trxGenerator(_date, _user):
    try:
        print(" >> trxGenerator() helper.")
        from datetime import datetime
        _now = datetime.now()
        _dateGen = _now.strftime("%d%m%YH%M%S")
        _trxId = randomString(2) + _dateGen + randomString(20)
        _trx_obj = {
            "date" : _date,
            "user" : _user,
            "id": _trxId
        }
        ### Por el momento no crearemos la trx por que antes necesitamos helpers para:
        ## - Eliminar trx por usuario.
        ## - eliminar trx por fecha
        ## - eliminar todas las transacciones.
        ## @TODO
        """
        if trx_ref.document(_trxId).set(_trx_obj):
            return _trxId
        else: 
            return False
        """
        return _trxId
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}
    
## Base64 encode
def b64Encode(_string):
    try:
        print(" >> b64Encode() helper.")
        _out = base64.b64encode(_string.encode('utf-8'))
        _r_out = str(_out, "utf-8")
        return _r_out
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## Base64 decode
def b64Decode(_string):
    try:
        print(" >> b64Decode() helper.")
        _out = base64.b64decode(_string).decode('utf-8')
        return _out
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## Current date: 
def currentDate():
    try:
        print(" >> currrentDate() helper.")
        from datetime import datetime
        _now = datetime.now()
        _now = _now.strftime("%d%m%YH%M%S")
        return _now
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)