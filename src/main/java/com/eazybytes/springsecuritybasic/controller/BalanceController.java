package com.eazybytes.springsecuritybasic.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BalanceController {
	
	@PostMapping("/myBalance")
	public String saceContactInquiryDetails() {
		return "Balance details from DB";
	}

}
