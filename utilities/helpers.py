import os, base64

class Helpers:
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
            userId = Helpers.currentDate()
            userId = Helpers.randomString(2) + userId + Helpers.randomString(_length)
            return userId
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## Transaction Number Generator
    def trxGenerator(_date, _user):
        try:
            print(" >> trxGenerator() helper.")
            from datetime import datetime
            _now = datetime.now()
            _dateGen = _now.strftime("%d%m%YH%M%S")
            _trxId = Helpers.randomString(2) + _dateGen + Helpers.randomString(20)
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