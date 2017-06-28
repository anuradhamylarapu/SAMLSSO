package com.mitra;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.apache.commons.httpclient.util.TimeoutController.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Anuradha.M on 6/16/17.
 * 
 * This class serves as RESTFUl web service to get the wellsource signed
 * assertion using SAMLSSO
 * 
 */
@Path("/getSAMLResponse")
public class SAMLSSOService {
	private final static Logger logger = LoggerFactory.getLogger(SAMLSSOService.class);

	@POST
	@Produces(MediaType.TEXT_PLAIN)
	public String processPostRequest(@FormParam("NameID") String nameID, @FormParam("AssmtGuid") String assmtGuid,
			@FormParam("GroupGuid") String groupGuid) throws Exception {
		logger.info("Entered into SAMLSSOService.processPostRequest() NameID: " + nameID + "GroupGuid: " + groupGuid
				+ "AssmtGuid: " + assmtGuid);
		SignAssertion signAssertion = new SignAssertion();
		String base64Response = null;
		try {
			base64Response = signAssertion.doSAMLSSO(nameID, groupGuid, assmtGuid);
		} catch (TimeoutException e) {
			e.printStackTrace();
			throw new Exception("Exception during the SAML response generation");
		}
		logger.info("Leaving SAMLSSOService.processPostRequest()");
		return base64Response;
	}

	@GET
	@Produces(MediaType.TEXT_PLAIN)
	public String processGetRequest(@QueryParam("NameID") String nameID, @QueryParam("AssmtGuid") String assmtGuid,
			@QueryParam("GroupGuid") String groupGuid) throws Exception {
		logger.info("Entered into SAMLSSOService.processGetRequest() NameID: " + nameID + "GroupGuid: " + groupGuid
				+ "AssmtGuid: " + assmtGuid);
		SignAssertion signAssertion = new SignAssertion();
		String base64Response = null;
		try {
			base64Response = signAssertion.doSAMLSSO(nameID, groupGuid, assmtGuid);
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception("Exception during the SAML response generation");
		}
		logger.info("Leaving SAMLSSOService.processGetRequest()");
		return base64Response;
	}

}
