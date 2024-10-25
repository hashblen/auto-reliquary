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

//! Generated file from `PNIOIKFKHHD.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:PNIOIKFKHHD)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct PNIOIKFKHHD {
    // message oneof groups
    pub CCELFAMIBKL: ::std::option::Option<pnioikfkhhd::CCELFAMIBKL>,
    // special fields
    // @@protoc_insertion_point(special_field:PNIOIKFKHHD.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a PNIOIKFKHHD {
    fn default() -> &'a PNIOIKFKHHD {
        <PNIOIKFKHHD as ::protobuf::Message>::default_instance()
    }
}

impl PNIOIKFKHHD {
    pub fn new() -> PNIOIKFKHHD {
        ::std::default::Default::default()
    }

    // .PHGIHOCABHE GOHKAOJCIDM = 15;

    pub fn GOHKAOJCIDM(&self) -> &super::PHGIHOCABHE::PHGIHOCABHE {
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(ref v)) => v,
            _ => <super::PHGIHOCABHE::PHGIHOCABHE as ::protobuf::Message>::default_instance(),
        }
    }

    pub fn clear_GOHKAOJCIDM(&mut self) {
        self.CCELFAMIBKL = ::std::option::Option::None;
    }

    pub fn has_GOHKAOJCIDM(&self) -> bool {
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_GOHKAOJCIDM(&mut self, v: super::PHGIHOCABHE::PHGIHOCABHE) {
        self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(v))
    }

    // Mutable pointer to the field.
    pub fn mut_GOHKAOJCIDM(&mut self) -> &mut super::PHGIHOCABHE::PHGIHOCABHE {
        if let ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(_)) = self.CCELFAMIBKL {
        } else {
            self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(super::PHGIHOCABHE::PHGIHOCABHE::new()));
        }
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_GOHKAOJCIDM(&mut self) -> super::PHGIHOCABHE::PHGIHOCABHE {
        if self.has_GOHKAOJCIDM() {
            match self.CCELFAMIBKL.take() {
                ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(v)) => v,
                _ => panic!(),
            }
        } else {
            super::PHGIHOCABHE::PHGIHOCABHE::new()
        }
    }

    // .PGIMFOFDPGF PGJKGLDABML = 2;

    pub fn PGJKGLDABML(&self) -> &super::PGIMFOFDPGF::PGIMFOFDPGF {
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(ref v)) => v,
            _ => <super::PGIMFOFDPGF::PGIMFOFDPGF as ::protobuf::Message>::default_instance(),
        }
    }

    pub fn clear_PGJKGLDABML(&mut self) {
        self.CCELFAMIBKL = ::std::option::Option::None;
    }

    pub fn has_PGJKGLDABML(&self) -> bool {
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_PGJKGLDABML(&mut self, v: super::PGIMFOFDPGF::PGIMFOFDPGF) {
        self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(v))
    }

    // Mutable pointer to the field.
    pub fn mut_PGJKGLDABML(&mut self) -> &mut super::PGIMFOFDPGF::PGIMFOFDPGF {
        if let ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(_)) = self.CCELFAMIBKL {
        } else {
            self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(super::PGIMFOFDPGF::PGIMFOFDPGF::new()));
        }
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_PGJKGLDABML(&mut self) -> super::PGIMFOFDPGF::PGIMFOFDPGF {
        if self.has_PGJKGLDABML() {
            match self.CCELFAMIBKL.take() {
                ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(v)) => v,
                _ => panic!(),
            }
        } else {
            super::PGIMFOFDPGF::PGIMFOFDPGF::new()
        }
    }

    // .MFDHINNNEGL NNLIGGHEBFP = 10;

    pub fn NNLIGGHEBFP(&self) -> &super::MFDHINNNEGL::MFDHINNNEGL {
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(ref v)) => v,
            _ => <super::MFDHINNNEGL::MFDHINNNEGL as ::protobuf::Message>::default_instance(),
        }
    }

    pub fn clear_NNLIGGHEBFP(&mut self) {
        self.CCELFAMIBKL = ::std::option::Option::None;
    }

    pub fn has_NNLIGGHEBFP(&self) -> bool {
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_NNLIGGHEBFP(&mut self, v: super::MFDHINNNEGL::MFDHINNNEGL) {
        self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(v))
    }

    // Mutable pointer to the field.
    pub fn mut_NNLIGGHEBFP(&mut self) -> &mut super::MFDHINNNEGL::MFDHINNNEGL {
        if let ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(_)) = self.CCELFAMIBKL {
        } else {
            self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(super::MFDHINNNEGL::MFDHINNNEGL::new()));
        }
        match self.CCELFAMIBKL {
            ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_NNLIGGHEBFP(&mut self) -> super::MFDHINNNEGL::MFDHINNNEGL {
        if self.has_NNLIGGHEBFP() {
            match self.CCELFAMIBKL.take() {
                ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(v)) => v,
                _ => panic!(),
            }
        } else {
            super::MFDHINNNEGL::MFDHINNNEGL::new()
        }
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(3);
        let mut oneofs = ::std::vec::Vec::with_capacity(1);
        fields.push(::protobuf::reflect::rt::v2::make_oneof_message_has_get_mut_set_accessor::<_, super::PHGIHOCABHE::PHGIHOCABHE>(
            "GOHKAOJCIDM",
            PNIOIKFKHHD::has_GOHKAOJCIDM,
            PNIOIKFKHHD::GOHKAOJCIDM,
            PNIOIKFKHHD::mut_GOHKAOJCIDM,
            PNIOIKFKHHD::set_GOHKAOJCIDM,
        ));
        fields.push(::protobuf::reflect::rt::v2::make_oneof_message_has_get_mut_set_accessor::<_, super::PGIMFOFDPGF::PGIMFOFDPGF>(
            "PGJKGLDABML",
            PNIOIKFKHHD::has_PGJKGLDABML,
            PNIOIKFKHHD::PGJKGLDABML,
            PNIOIKFKHHD::mut_PGJKGLDABML,
            PNIOIKFKHHD::set_PGJKGLDABML,
        ));
        fields.push(::protobuf::reflect::rt::v2::make_oneof_message_has_get_mut_set_accessor::<_, super::MFDHINNNEGL::MFDHINNNEGL>(
            "NNLIGGHEBFP",
            PNIOIKFKHHD::has_NNLIGGHEBFP,
            PNIOIKFKHHD::NNLIGGHEBFP,
            PNIOIKFKHHD::mut_NNLIGGHEBFP,
            PNIOIKFKHHD::set_NNLIGGHEBFP,
        ));
        oneofs.push(pnioikfkhhd::CCELFAMIBKL::generated_oneof_descriptor_data());
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<PNIOIKFKHHD>(
            "PNIOIKFKHHD",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for PNIOIKFKHHD {
    const NAME: &'static str = "PNIOIKFKHHD";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                122 => {
                    self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(is.read_message()?));
                },
                18 => {
                    self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(is.read_message()?));
                },
                82 => {
                    self.CCELFAMIBKL = ::std::option::Option::Some(pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(is.read_message()?));
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let ::std::option::Option::Some(ref v) = self.CCELFAMIBKL {
            match v {
                &pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
                },
                &pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
                },
                &pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
                },
            };
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let ::std::option::Option::Some(ref v) = self.CCELFAMIBKL {
            match v {
                &pnioikfkhhd::CCELFAMIBKL::GOHKAOJCIDM(ref v) => {
                    ::protobuf::rt::write_message_field_with_cached_size(15, v, os)?;
                },
                &pnioikfkhhd::CCELFAMIBKL::PGJKGLDABML(ref v) => {
                    ::protobuf::rt::write_message_field_with_cached_size(2, v, os)?;
                },
                &pnioikfkhhd::CCELFAMIBKL::NNLIGGHEBFP(ref v) => {
                    ::protobuf::rt::write_message_field_with_cached_size(10, v, os)?;
                },
            };
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> PNIOIKFKHHD {
        PNIOIKFKHHD::new()
    }

    fn clear(&mut self) {
        self.CCELFAMIBKL = ::std::option::Option::None;
        self.CCELFAMIBKL = ::std::option::Option::None;
        self.CCELFAMIBKL = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static PNIOIKFKHHD {
        static instance: PNIOIKFKHHD = PNIOIKFKHHD {
            CCELFAMIBKL: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for PNIOIKFKHHD {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("PNIOIKFKHHD").unwrap()).clone()
    }
}

impl ::std::fmt::Display for PNIOIKFKHHD {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PNIOIKFKHHD {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

/// Nested message and enums of message `PNIOIKFKHHD`
pub mod pnioikfkhhd {

    #[derive(Clone,PartialEq,Debug)]
    #[non_exhaustive]
    // @@protoc_insertion_point(oneof:PNIOIKFKHHD.CCELFAMIBKL)
    pub enum CCELFAMIBKL {
        // @@protoc_insertion_point(oneof_field:PNIOIKFKHHD.GOHKAOJCIDM)
        GOHKAOJCIDM(super::super::PHGIHOCABHE::PHGIHOCABHE),
        // @@protoc_insertion_point(oneof_field:PNIOIKFKHHD.PGJKGLDABML)
        PGJKGLDABML(super::super::PGIMFOFDPGF::PGIMFOFDPGF),
        // @@protoc_insertion_point(oneof_field:PNIOIKFKHHD.NNLIGGHEBFP)
        NNLIGGHEBFP(super::super::MFDHINNNEGL::MFDHINNNEGL),
    }

    impl ::protobuf::Oneof for CCELFAMIBKL {
    }

    impl ::protobuf::OneofFull for CCELFAMIBKL {
        fn descriptor() -> ::protobuf::reflect::OneofDescriptor {
            static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::OneofDescriptor> = ::protobuf::rt::Lazy::new();
            descriptor.get(|| <super::PNIOIKFKHHD as ::protobuf::MessageFull>::descriptor().oneof_by_name("CCELFAMIBKL").unwrap()).clone()
        }
    }

    impl CCELFAMIBKL {
        pub(in super) fn generated_oneof_descriptor_data() -> ::protobuf::reflect::GeneratedOneofDescriptorData {
            ::protobuf::reflect::GeneratedOneofDescriptorData::new::<CCELFAMIBKL>("CCELFAMIBKL")
        }
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x11PNIOIKFKHHD.proto\x1a\x11MFDHINNNEGL.proto\x1a\x11PGIMFOFDPGF.prot\
    o\x1a\x11PHGIHOCABHE.proto\"\xb2\x01\n\x0bPNIOIKFKHHD\x120\n\x0bGOHKAOJC\
    IDM\x18\x0f\x20\x01(\x0b2\x0c.PHGIHOCABHEH\0R\x0bGOHKAOJCIDM\x120\n\x0bP\
    GJKGLDABML\x18\x02\x20\x01(\x0b2\x0c.PGIMFOFDPGFH\0R\x0bPGJKGLDABML\x120\
    \n\x0bNNLIGGHEBFP\x18\n\x20\x01(\x0b2\x0c.MFDHINNNEGLH\0R\x0bNNLIGGHEBFP\
    B\r\n\x0bCCELFAMIBKLb\x06proto3\
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
            let mut deps = ::std::vec::Vec::with_capacity(3);
            deps.push(super::MFDHINNNEGL::file_descriptor().clone());
            deps.push(super::PGIMFOFDPGF::file_descriptor().clone());
            deps.push(super::PHGIHOCABHE::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(PNIOIKFKHHD::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
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