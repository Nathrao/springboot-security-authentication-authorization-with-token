package com.jspringboot.auth.product.dto;

import lombok.Data;

@Data
public class ProductDetails {
	private Integer id;
	private String productName;
	private String uniqueCode;

}
