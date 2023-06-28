package com.jspringboot.auth.product.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jspringboot.auth.product.dto.ProductDetails;

@RestController
@RequestMapping(value = "/product")
public class ProductController {

	public static final String PERMIT_INTERNAL_USER = "hasRole('ROLE_ADMIN') or hasRole('ROLE_OPERATIONS')";
	public static final String PERMIT_INTERNAL_ADMIN = "hasRole('ROLE_ADMIN')";
	public static final String PERMIT_INTERNAL_OPERATION = "hasRole('ROLE_OPERATIONS')";
	
	@PreAuthorize(PERMIT_INTERNAL_USER)
	@GetMapping("/id/{id}")
	public ProductDetails getProduct(@PathVariable(name = "id") Integer id) {
		ProductDetails details = new ProductDetails();
		details.setId(1);
		return details;
	}

	@PreAuthorize(PERMIT_INTERNAL_ADMIN)
	@GetMapping("/name/{productName}")
	public ProductDetails getProductName(@PathVariable(name = "productName") String productName) {
		ProductDetails details = new ProductDetails();
		details.setId(1);
		details.setProductName("sample");
		return details;
	}

	@PreAuthorize(PERMIT_INTERNAL_OPERATION)
	@GetMapping("/code/{uniqueCode}")
	public ProductDetails getUniqueCode(@PathVariable(name = "uniqueCode") String uniqueCode) {
		ProductDetails details = new ProductDetails();
		details.setId(1);
		details.setProductName("sample");
		details.setUniqueCode("AnjNkRnCmc-XY9FhtysC4");
		return details;
	}

}
