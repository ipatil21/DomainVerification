#-------------------------------------------------------------------------------
# Name:        LGDomainVerify
# Purpose:     Web-Service to verify & validate Domain
# Author:      Indraneel Patil
# Created:     07-03-2018
# Copyright:   KTPL
#-------------------------------------------------------------------------------

# define
DEBUG               =   False
SPACE               =   str(" ")
QUOTE               =   str("'")

import json
import whois
import validators
from flask import Flask

app = Flask(__name__)

def FormatString(retVal):

       if(QUOTE in str(retVal.creation_date)):
            retVal.creation_date = str(retVal.creation_date).split("'")[1]
            retVal.creation_date = retVal.creation_date.split("T")[0]
            retVal.expiration_date = str(retVal.expiration_date).split("'")[1]
            retVal.expiration_date = retVal.expiration_date.split("T")[0]
            retVal.updated_date = str(retVal.updated_date).split("'")[1]
            retVal.updated_date = retVal.updated_date.split("T")[0]

       else:
            retVal.creation_date = str(retVal.creation_date).split(" ")[0]
            retVal.expiration_date = str(retVal.expiration_date).split(" ")[0]
            retVal.updated_date = str(retVal.updated_date).split(" ")[0]

def OutputLogs(debugLevel, forceLogs, logStatement):
    if ((True == debugLevel) or (True == forceLogs)):
        print logStatement

@app.route('/LGVerifyDomain/<domain>')
def DomainVerify(domain):

    OutputLogs(DEBUG, False, "DomainVerify Function Start");
    operation = True
    outJson = {}

    if(True == validators.domain(domain)):
        try:
            retVal = whois.whois(domain)
            print retVal;
            outJson[domain] = "True"
            OutputLogs(DEBUG, True, domain + SPACE + '- Domain Verfied')

        except:
            operation = False
            outJson[domain] = "False"
            OutputLogs(DEBUG, True, domain + ' - Domain Verfication Failed')

        if(True == operation):
            FormatString(retVal)
            OutputLogs(DEBUG, True, 'Registration Date - ' + retVal.creation_date)
            OutputLogs(DEBUG, True, 'Expiration Date  - ' + retVal.expiration_date)

            OutputLogs(DEBUG, True, retVal.updated_date)
            outJson['Reg Date'] = retVal.creation_date
            outJson['Exp Date'] = retVal.expiration_date

            OutputLogs(DEBUG, False, "Domain Verify Function End");
        else:
            outJson['Reg Date'] = "None"
            outJson['Exp Date'] = "None"
    else:
        outJson[domain] = "Invalid"

    return json.dumps(outJson, indent=4)

@app.route('/')
def main():
    return '!!! Welcome to LoanGuard Sevices !!! '

if __name__ == '__main__':
    app.run(host= '45.64.105.209', port = 2111, debug=True)
