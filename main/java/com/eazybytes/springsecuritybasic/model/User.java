package com.eazybytes.springsecuritybasic.model;

public class User {

	private int number;
	private String name;
	private String mobileNumber;
	private String email;
	private String password;
	private String role;
	private String statusMsg;
	private String authStatus;
	
	public int getNumber() {
		return number;
	}
	public void setNumber(int number) {
		this.number = number;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getMobileNumber() {
		return mobileNumber;
	}
	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	public String getStatusMsg() {
		return statusMsg;
	}
	public void setStatusMsg(String statusMsg) {
		this.statusMsg = statusMsg;
	}
	public String getAuthStatus() {
		return authStatus;
	}
	public void setAuthStatus(String authStatus) {
		this.authStatus = authStatus;
	}
	@Override
	public String toString() {
		return "User [number=" + number + ", name=" + name + ", mobileNumber=" + mobileNumber + ", email=" + email
				+ ", password=" + password + ", role=" + role + ", statusMsg=" + statusMsg + ", authStatus="
				+ authStatus + "]";
	}
	
}
