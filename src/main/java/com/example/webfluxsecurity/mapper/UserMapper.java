package com.example.webfluxsecurity.mapper;

import com.example.webfluxsecurity.dto.UserDto;
import com.example.webfluxsecurity.entity.UserEntity;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDto mapToDto(UserEntity entity);

    @InheritInverseConfiguration
    UserEntity mapToEntity(UserDto dto);
}
