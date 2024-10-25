// This file is generated by rust-protobuf 3.4.0. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `BattleModuleType.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
// @@protoc_insertion_point(enum:BattleModuleType)
pub enum BattleModuleType {
    // @@protoc_insertion_point(enum_value:BattleModuleType.BATTLE_MODULE_MAZE)
    BATTLE_MODULE_MAZE = 0,
    // @@protoc_insertion_point(enum_value:BattleModuleType.BATTLE_MODULE_CHALLENGE)
    BATTLE_MODULE_CHALLENGE = 1,
    // @@protoc_insertion_point(enum_value:BattleModuleType.BATTLE_MODULE_COCOON)
    BATTLE_MODULE_COCOON = 2,
    // @@protoc_insertion_point(enum_value:BattleModuleType.BATTLE_MODULE_ROGUE)
    BATTLE_MODULE_ROGUE = 3,
    // @@protoc_insertion_point(enum_value:BattleModuleType.BATTLE_MODULE_CHALLENGE_ACTIVITY)
    BATTLE_MODULE_CHALLENGE_ACTIVITY = 4,
    // @@protoc_insertion_point(enum_value:BattleModuleType.BATTLE_MODULE_TRIAL_LEVEL)
    BATTLE_MODULE_TRIAL_LEVEL = 5,
    // @@protoc_insertion_point(enum_value:BattleModuleType.BATTLE_MODULE_AETHER_DIVIDE)
    BATTLE_MODULE_AETHER_DIVIDE = 6,
}

impl ::protobuf::Enum for BattleModuleType {
    const NAME: &'static str = "BattleModuleType";

    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<BattleModuleType> {
        match value {
            0 => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_MAZE),
            1 => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_CHALLENGE),
            2 => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_COCOON),
            3 => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_ROGUE),
            4 => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_CHALLENGE_ACTIVITY),
            5 => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_TRIAL_LEVEL),
            6 => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_AETHER_DIVIDE),
            _ => ::std::option::Option::None
        }
    }

    fn from_str(str: &str) -> ::std::option::Option<BattleModuleType> {
        match str {
            "BATTLE_MODULE_MAZE" => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_MAZE),
            "BATTLE_MODULE_CHALLENGE" => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_CHALLENGE),
            "BATTLE_MODULE_COCOON" => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_COCOON),
            "BATTLE_MODULE_ROGUE" => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_ROGUE),
            "BATTLE_MODULE_CHALLENGE_ACTIVITY" => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_CHALLENGE_ACTIVITY),
            "BATTLE_MODULE_TRIAL_LEVEL" => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_TRIAL_LEVEL),
            "BATTLE_MODULE_AETHER_DIVIDE" => ::std::option::Option::Some(BattleModuleType::BATTLE_MODULE_AETHER_DIVIDE),
            _ => ::std::option::Option::None
        }
    }

    const VALUES: &'static [BattleModuleType] = &[
        BattleModuleType::BATTLE_MODULE_MAZE,
        BattleModuleType::BATTLE_MODULE_CHALLENGE,
        BattleModuleType::BATTLE_MODULE_COCOON,
        BattleModuleType::BATTLE_MODULE_ROGUE,
        BattleModuleType::BATTLE_MODULE_CHALLENGE_ACTIVITY,
        BattleModuleType::BATTLE_MODULE_TRIAL_LEVEL,
        BattleModuleType::BATTLE_MODULE_AETHER_DIVIDE,
    ];
}

impl ::protobuf::EnumFull for BattleModuleType {
    fn enum_descriptor() -> ::protobuf::reflect::EnumDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().enum_by_package_relative_name("BattleModuleType").unwrap()).clone()
    }

    fn descriptor(&self) -> ::protobuf::reflect::EnumValueDescriptor {
        let index = *self as usize;
        Self::enum_descriptor().value_by_index(index)
    }
}

impl ::std::default::Default for BattleModuleType {
    fn default() -> Self {
        BattleModuleType::BATTLE_MODULE_MAZE
    }
}

impl BattleModuleType {
    fn generated_enum_descriptor_data() -> ::protobuf::reflect::GeneratedEnumDescriptorData {
        ::protobuf::reflect::GeneratedEnumDescriptorData::new::<BattleModuleType>("BattleModuleType")
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x16BattleModuleType.proto*\xe0\x01\n\x10BattleModuleType\x12\x16\n\
    \x12BATTLE_MODULE_MAZE\x10\0\x12\x1b\n\x17BATTLE_MODULE_CHALLENGE\x10\
    \x01\x12\x18\n\x14BATTLE_MODULE_COCOON\x10\x02\x12\x17\n\x13BATTLE_MODUL\
    E_ROGUE\x10\x03\x12$\n\x20BATTLE_MODULE_CHALLENGE_ACTIVITY\x10\x04\x12\
    \x1d\n\x19BATTLE_MODULE_TRIAL_LEVEL\x10\x05\x12\x1f\n\x1bBATTLE_MODULE_A\
    ETHER_DIVIDE\x10\x06b\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(0);
            let mut messages = ::std::vec::Vec::with_capacity(0);
            let mut enums = ::std::vec::Vec::with_capacity(1);
            enums.push(BattleModuleType::generated_enum_descriptor_data());
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}