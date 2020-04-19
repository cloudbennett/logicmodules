import org.apache.http.HttpEntity
import org.apache.http.client.entity.EntityBuilder
import org.apache.http.util.EntityUtils
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Hex
import groovy.json.JsonSlurper

// *** Get LM Device Properties
def accessKey = hostProps.get("lm.access.key")
def accessID = hostProps.get("lm.access.id")
def eventWarn = hostProps.get("lm.auditlogs.warn")
def eventError = hostProps.get("lm.auditlogs.error")
def eventCritical = hostProps.get("lm.auditlogs.critical")
def hostname = hostProps.get("system.hostname")

// *** Get current time (now - 60s)
def epochCurrentSeconds = System.currentTimeSeconds()
def epochPreviousSeconds = epochCurrentSeconds - 60
def epochCurrentMillis = System.currentTimeMillis()

// *** Setup URL
def baseUrl = "https://" + hostname + "/santaba/rest"
def endpoint = "/setting/accesslogs"
// "happenedOn>:" set filter to only grab Audit Logs after a designated epoch timestamp
def queryParams = "?filter=happenedOn%3E%3A" + epochPreviousSeconds + "&size=1000"
def apiUrl = baseUrl + endpoint + queryParams

// *** Setup LM API auth
def requestVars = "GET" + epochCurrentMillis + endpoint
def hmac = Mac.getInstance("HmacSHA256")
def secret = new SecretKeySpec(accessKey.getBytes(), "HmacSHA256")
hmac.init(secret)
def hmacSigned = Hex.encodeHexString(hmac.doFinal(requestVars.getBytes()))
def signature = hmacSigned.bytes.encodeBase64()

// *** LM API HTTP Get
CloseableHttpClient httpclient = HttpClients.createDefault()
def httpGet = new HttpGet(apiUrl)
def authValue = "LMv1 " + accessID + ":" + signature + ":" + epochCurrentMillis
httpGet.addHeader("Authorization" , authValue)
def httpResponse = httpclient.execute(httpGet)
def httpResponseBody = EntityUtils.toString(httpResponse.getEntity())
def httpResponseCode = httpResponse.getStatusLine().getStatusCode()
httpclient.close()

// *** Parse LM Audit Logs JSON
def jsonSlurper = new JsonSlurper()
def auditLogs = jsonSlurper.parseText(httpResponseBody)

// *** Create string for standard output
String jsonOutput = '{"events":['
// If there are new Audit Logs
if (auditLogs.data.total > 0) {
    // Iterate through Event within the Audit Logs
    auditLogs.data.items.each { auditLog ->
        // Look for the regex match in the Audit Log's description based on the LM Device Property
        String description = auditLog.description
        String username = auditLog.username
        String ip = auditLog.ip
        if (description =~ eventWarn || username =~ eventWarn || ip =~ eventWarn) {
            jsonOutput = jsonOutput.concat('{"happenedOn":"' + auditLog.happenedOnLocal + '","severity":"warn","message":"username: ' + username + ', ip: ' + ip + ', description: ' + description + '"},')
        }
        else if (description =~ eventError || username =~ eventError || ip =~ eventError) {
            jsonOutput = jsonOutput.concat('{"happenedOn":"' + auditLog.happenedOnLocal + '","severity":"error","message":"username: ' + username + ', ip: ' + ip + ', description: ' + description + '"},')
        }
        else if (description =~ eventCritical || username =~ eventCritical || ip =~ eventCritical) {
            jsonOutput = jsonOutput.concat('{"happenedOn":"' + auditLog.happenedOnLocal + '","severity":"critical","message":"username: ' + username + ', ip: ' + ip + ', description: ' + description + '"},')
        }
    }
}

jsonOutput = jsonOutput.concat(']}')

// Print standard output
println jsonOutput

return 0