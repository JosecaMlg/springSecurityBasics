package com.eazybytes.springsecuritybasic.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {
	
	@PostMapping("/contact")
	public String saceContactInquiryDetails() {
		return "Message Sent!";
	}

}
