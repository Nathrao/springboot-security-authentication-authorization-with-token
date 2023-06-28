package com.jspringboot.auth.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.jspringboot.auth.user.entity.UserEntity;


public interface UserRepository extends JpaRepository<UserEntity, Integer> {

	Optional<UserEntity> findByName(String name);

}
