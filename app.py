## Flask API for adminde-tc project.
## Pylexandria Project.
## Coded by: Mauricio Alcala (@maualkla)
## Creation Date: May 2023.
## Current Version: 0.02
## Last Modification Date: July 2023.
## More info at @intmau in twitter or in http://maualkla.com
## Description: API for the services required by the adminde-tc proyect.

## Imports
from flask import Flask, jsonify, request, render_template
from firebase_admin import credentials, firestore, initialize_app
from config import Config
import os, rsa, bcrypt, base64, json

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

## Session Service (new login)
@app.route('/session', methods=['GET', 'POST', 'DELETE'])
def session():
    try:
        ## Method: GET /session
        if request.method == 'GET':
            ## code for post
            return "1"
        ## Method: POST /session
        elif request.method == 'POST': 
            return "2"
        ## Method: DELETE /session
        elif request.method == 'DELETE': 
            return "3"
        else:
            return jsonify({"status": "Error", "code": 405, "reason": "Method Not Allowed"}), 405
    except Exception as e: 
        return {"status":"Error", "code": "500", "reason": str(e)}

## Login service (deprecated)
@app.route("/login", methods=['GET'])
def login():
    try:
        ### validate parameters
        if 'u' not in request.args or 'p' not in request.args:
            return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields"}), 400
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
                    return jsonify({"expire": _token['expire'], "id": _token['id'], "username": _token['username'], "trxId": trxGenerator(currentDate(), _username)}), 200
                else:
                    return jsonify({"status": "Error", "code": "401", "reason": "Not Authorized, review user or password"}), 401
            else:
                return jsonify({"status": "Error", "code": "404", "reason": "Not Authorized, review user or password"}), 404
    except Exception as e: 
        return {"status":"Error", "code": "500", "reason": str(e)}

## Logout Service
@app.route('/logout', methods=['GET'])
def logout():
    try:
        ### validate parameters
        if '_id' not in request.args or '_username' not in request.args:
            ## Return error response, missing required fields
            return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields"}), 400
        else: 
            ## get and decode the request parameter
            _username = request.args.get('_username')
            _username = b64Decode(_username)
            ## Delete all user related tokens.
            _tokens = deleteUserTokens(_username)
            trxGenerator(currentDate(), _username)
            ## Return 440 logout http response code.
            if _tokens > 0:
                return jsonify({"status": "success", "code": "440", "reason": "session closed"}), 440
            else:
                return jsonify({"status": "error", "code": "404", "reason": "User not logged."}), 404
    except Exception as e: 
        return {"status":"Error", "code": "500", "reason": str(e)}

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
                    _user_post_params = ['activate','username','bday','email','fname','phone','pin','plan','postalCode','terms','type']
                    _pcode = request.json['pass']
                    _pcode = b64Decode(_pcode)
                    _pwrd = encrypt(_pcode)
                    ## Create object to create the new user.
                    _objpay = {}
                    for _x in _user_post_params:
                        _objpay[_x] = request.json[_x]
                    _objpay['pass'] = _pwrd
                    ## Get current date
                    _tempdate = str(currentDate())
                    ## send new user to be created, if created return 202 code and trxId code, else return 500 error while creating
                    if users_ref.document(s_email).set(_objpay):
                        return jsonify({"trxId": trxGenerator(_tempdate,s_email)}), 202
                    else:
                        return jsonify({"status": "Error", "code": "500", "reason": "Error while creating user. "}), 500
                else:
                    return jsonify({"status": "Error", "code": "409", "reason": "Email already registered" }), 409
            else: 
                return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields"}), 400
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
        return jsonify({"status": vauth.json['status'], "alert": "this service is deprecated and will be removed by v0.03 - Use the /auth service instead."}), 200
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}
    
## Auth a token.
@app.route('/auth', methods=['POST'])
def auth():
    try:
        ## Validate if required fields are in the json request.
        if 'id' not in request.json or 'username' not in request.json:
            ## Return error response, missing required fields
            return jsonify({"status": "Error", "code": "400", "reason": "Missing required fields"}), 400
        else: 
            ## go to tokenValidator and retrieve a valid or expired status.
            _auth = tokenValidator(request.json['username'], request.json['id'])
            ## return the tokenvalidator status and a 200 code.
            return _auth, 200
    except Exception as e:
        return {"status":"Error", "code": "500", "reason": str(e)}

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
def idGenerator():
    try:
        print(" >> idGenerator() helper.")
        userId = currentDate()
        userId = randomString(2) + userId + randomString(10)
        return userId
    except Exception as e:
        return {"status": "An error Occurred", "error": str(e)}

## token generator
def tokenGenerator(_user, _ilimited):
    try:
        print(" >> tokenGenerator() helper.")
        from datetime import datetime, timedelta
        current_date_time = datetime.now()
        token = idGenerator()
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
            return tobj
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
                    return jsonify({"status": "valid"})
                else: 
                    deleteToken(_token)
                    return jsonify({"status": "expired"})
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
    _tokens = tokens_ref.where('username', '==', _un)
    _tokens_count = 0
    ## for each token returned
    for _tok in _tokens.stream():
        ## if inside, _exists = true and delete current token
        _exists = True
        deleteToken(_tok.id)
        _tokens_count += 1
    return _tokens_count


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
    app.run(debug=True, port=5000)