## time Log Service 
@app.route('/timeLog', methods=['GET','POST','UPDATE','DELETE'])
def timeLog():
    try:
        ## Method: POST /timeLog
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
                ## Look for the timeLog to exist.
                if 'Id' in request.json:
                    ## Search for a wsp with that TaxId
                    _tnun_exist = tentus_ref.document(request.json['Id']).get()
                    ## format the json object
                    _tnun_exist = _tnun_exist.to_dict()
                ## If the wsp with that taxId do not exists proceeeds, otherwise return a 403 http code.
                if _tnun_exist == None:
                    ## Validate required values, first creating a list of all required
                    req_fields = ['Active', 'Edited', 'EditedBy', 'EditionDate', 'EndTime', 'OriginalEndTime', 'OriginalStartTime', 'StartTime', 'UserId']
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
                        # create timeLog.
                        try:
                            ## Call to create the timeLog.
                            tentus_ref.document(request.json['Id']).set(_json_payload)
                        except Exception as e:
                            ## In case of an error updating the user, retrieve a error message.
                            print('(!) >> Handled external service exception: ' + str(e) )
                            return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "timeLog cannot be updated."}), int(str(e)[0:3])
                        ## in case the ws is created, returns 200 abd the trxId 
                        return jsonify({"status": "success", "code": 200, "reason": "timeLog created succesfully.", "trxId": transactionPost(request.json['CreatedBy'],False, 1, "Tenant User POST")}), 200
                    else:
                        ## in case any required field is not present, will return a 400
                        return jsonify({"status": "Error", "code": 400, "reason": "Missing required fields"}), 400
                else: 
                    ## In case ws TaxId is already registered, will trwo a 403 error.
                    return jsonify({"status": "Error", "code": 403, "reason": "timeLog TaxId already registered."}), 403
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## Method: PUT /timeLog
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
                ## Look for the timeLog to exist.
                if 'Id' in request.json and 'Tenant' in request.json:
                    ## Search for a wsp with that TaxId
                    _tnun_exist = tentus_ref.document(request.json['id'])
                    ## format the json object to get values from it
                    _fs_user = _tnun_exist.get().to_dict()
                    ## continue if a timeLog with the taxId send already exist and the owner match.
                    if _tnun_exist != None and _fs_user['Tenant'] == request.json['Tenant']:
                        ## Creation of the optional fields that could be sent to update the timeLog.
                        req_fields = ['Username', 'Password', 'FullName', 'Email', 'Manager', 'Type']
                        ## define a flag to send or not the request.
                        _go = False
                        ## Create json template for the payload
                        _json_template = '{ }'
                        ## Load the json payload 
                        _json_payload = json.loads(_json_template)
                        ## Create a for loop addressing all the required fields
                        for req_value in req_fields:
                            ## In case required field in json payload 
                            if req_value in request.json:
                                ## update _json_payload object adding current field.
                                _json_payload.update({req_value: request.json[req_value]})
                                ## update flag to update user
                                _go = True
                        if _go:
                            try:
                                ## Call to create the timeLog.
                                _response = _tnun_exist.update(_json_payload)
                            except Exception as e:
                                ## In case of an error updating the user, retrieve a error message.
                                print('(!) >> Handled external service exception: ' + str(e) )
                                return jsonify({"status":"Error", "code": str(e)[0:3], "reason": "User cannot be updated."}), int(str(e)[0:3])
                            ## in case the ws is created, returns 200 abd the trxId 
                            return jsonify({"status": "success", "code": 202, "reason": "timeLog updated succesfully.", "trxId": transactionPost(request.json['Owner'], False, 1, "timeLog Put")}), 202
                        else:
                            ## in case any required field is not present, will return a 400
                            return jsonify({"status": "Error", "code": 400, "reason": "No fields to be updated, review the request."}), 400
                    else:
                        ## In case ws TaxId is already registered, will trwo a 403 error.
                        return jsonify({"status": "Error", "code": 403, "reason": "timeLog not found or Owner user does not match. Review the payload and try again."}), 403
                else:
                    ## in case any required field is not present, will return a 400
                    return jsonify({"status": "Error", "code": 400, "reason": "Review request payload"}), 400
            else:
                ## Missing authorization headers.
                return jsonify({"status": "Error", "code": 401, "reason": "Invalid Authorization"}), 401
        ## Method: GET /timeLog
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
                req_fields = ['Username', 'Id', 'Password', 'FullName', 'Email', 'Manager', 'Tenant', 'Type', 'CreatedBy']
                ### Set the base for the json block to be returned. Define the data index for the list of users
                _json_data_block = {"items": []}
                ## If query filter present in url params it will save it, else will set False.
                _query = False if 'filter' not in request.args else request.args.get('filter')
                ## If id filter present in url params it will save it, else will set false.
                _id = False if 'id' not in request.args else request.args.get('id')
                ## set default value for limit and count. 
                _limit =  10 
                _count = 0
                _tenant = False
                _manager = False
                _active = "N"

                ## Validate if _query present
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if limit param present set the limit value
                    _limit = int(_parameters['limit']) if 'limit' in _parameters else _limit
                    ## if tenant param present, set the owner param
                    _tenant = str(_parameters['tenant']) if 'tenant' in _parameters else _tenant
                    ## if shortCode param present, set the shortCode param
                    _manager = str(_parameters['manager']) if 'manager' in _parameters else _manager
                    ## if active param present validates the str value, if true seet True, else set False. if not present, 
                    ## sets _active to "N" to ignore the value
                    if 'active' in _parameters:
                        _active = True if str(_parameters['active']).lower() == 'true' else False
                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = tentus_ref.where(filter=FieldFilter("Id", "==", _id))
                elif _manager: 
                    ## the case of shortCode is present wull search for it.
                    _search = tentus_ref.where(filter=FieldFilter("manager", "==", _manager))
                elif _tenant:
                    ## The case username is present, will search with the specific username. 
                    _search = tentus_ref.where(filter=FieldFilter("tenant", "==", _tenant))
                    if _active != "N":
                        ## In case the _active param is present in valid fashion, will search for active or inactiv
                        ## e users.
                        _search = _search.where(filter=FieldFilter("Active", "==", _active))
                elif _active != "N":
                    ## In case activate is present, will search for active or inactive users.
                    _search = tentus_ref.where(filter=FieldFilter("Active", "==", _active))
                else:
                    ## In case any param was present, will search all
                    _search = tentus_ref
                ## Loop in all the users inside the users_ref object
                for _ws in _search.stream():
                    ## set the temporal json_blocl
                    _json_block_l = {}
                    ## apply the to_dict() to the current user to use their information.
                    _acc = _ws.to_dict()
                    ## Add a +1 to the count
                    _count += 1
                    ## Iterates into the _user_fields object to generate the json object for that user.
                    for _x in req_fields:
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
                _tenant = False
                _manager = False
                _active = "N"

                ## Validate if _query present
                if _query:
                    ## calls to splitParams sending the _query form the request. If query correct returns a 
                    ## dictionary with the params as key value.
                    _parameters = Helpers.splitParams(_query)
                    ## if username param present, set the owner param
                    _tenant = str(_parameters['tenant']) if 'tenant' in _parameters else _tenant
                    ## if shortCode param present, set the shortCode param
                    _manager = str(_parameters['manager']) if 'shortCode' in _parameters else _manager
                    ## if active param present validates the str value, if true seet True, else set False. if not present, 
                    ## sets _active to "N" to ignore the value
                    if 'active' in _parameters:
                        _active = True if str(_parameters['active']).lower() == 'true' else False
                        
                ## Logic to get data
                ## Validate the 4 possible combinations for the query of the users search
                if _id:
                    ## The case of id is present will search for that specific email
                    _search = tentus_ref.where(filter=FieldFilter("Id", "==", _id))
                elif _manager: 
                    ## the case of shortCode is present wull search for it.
                    _search = tentus_ref.where(filter=FieldFilter("Manager", "==", _manager))
                    if _active != "N":
                        ## In case the _active param is present in valid fashion, will search for active or inactiv
                        ## e users.
                        _search = _search.where(filter=FieldFilter("Active", "==", _active))
                elif _tenant:
                    ## The case username is present, will search with the specific username. 
                    _search = tentus_ref.where(filter=FieldFilter("Tenant", "==", _tenant))
                    if _active != "N":
                        ## In case the _active param is present in valid fashion, will search for active or inactiv
                        ## e users.
                        _search = _search.where(filter=FieldFilter("Active", "==", _active))
                else:
                    ## In case any param was present, will search all
                    _search = tentus_ref.where(filter=FieldFilter("Id", "==", ""))

                ## Loop in all the users inside the users_ref object
                _trx = {}
                for _us in _search.stream():
                    ## apply the to_dict() to the current user to use their information.
                    _acc = _us.to_dict()
                    ## validate if deletion was successful
                    if deleteWorkspace(_acc['Id']):
                        ## Add the trx number to the user email to the return response
                        _trx[_acc['Id']] = transactionPost(_auth['CreatedBy'], False, 2, "timeLog Delete")
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