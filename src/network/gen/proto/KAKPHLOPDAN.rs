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

//! Generated file from `KAKPHLOPDAN.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:KAKPHLOPDAN)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct KAKPHLOPDAN {
    // message fields
    // @@protoc_insertion_point(field:KAKPHLOPDAN.FJIOMCLFLMK)
    pub FJIOMCLFLMK: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.KCNBAPCDOAC)
    pub KCNBAPCDOAC: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.HPEHGIGBKFH)
    pub HPEHGIGBKFH: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.IMKELKMHOIK)
    pub IMKELKMHOIK: ::protobuf::MessageField<super::DHPIFKICOPP::DHPIFKICOPP>,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.FGCPMGKNMOK)
    pub FGCPMGKNMOK: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.IGDJLMDKHCJ)
    pub IGDJLMDKHCJ: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.FILMAOEBILH)
    pub FILMAOEBILH: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.IFPEPCBOJKJ)
    pub IFPEPCBOJKJ: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.ENEOHGOGJHO)
    pub ENEOHGOGJHO: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.PNNKEEFNNOI)
    pub PNNKEEFNNOI: u32,
    // @@protoc_insertion_point(field:KAKPHLOPDAN.CMCBBHJELBD)
    pub CMCBBHJELBD: ::protobuf::EnumOrUnknown<super::BLBJBAMDNBN::BLBJBAMDNBN>,
    // special fields
    // @@protoc_insertion_point(special_field:KAKPHLOPDAN.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a KAKPHLOPDAN {
    fn default() -> &'a KAKPHLOPDAN {
        <KAKPHLOPDAN as ::protobuf::Message>::default_instance()
    }
}

impl KAKPHLOPDAN {
    pub fn new() -> KAKPHLOPDAN {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(11);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "FJIOMCLFLMK",
            |m: &KAKPHLOPDAN| { &m.FJIOMCLFLMK },
            |m: &mut KAKPHLOPDAN| { &mut m.FJIOMCLFLMK },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "KCNBAPCDOAC",
            |m: &KAKPHLOPDAN| { &m.KCNBAPCDOAC },
            |m: &mut KAKPHLOPDAN| { &mut m.KCNBAPCDOAC },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "HPEHGIGBKFH",
            |m: &KAKPHLOPDAN| { &m.HPEHGIGBKFH },
            |m: &mut KAKPHLOPDAN| { &mut m.HPEHGIGBKFH },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::DHPIFKICOPP::DHPIFKICOPP>(
            "IMKELKMHOIK",
            |m: &KAKPHLOPDAN| { &m.IMKELKMHOIK },
            |m: &mut KAKPHLOPDAN| { &mut m.IMKELKMHOIK },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "FGCPMGKNMOK",
            |m: &KAKPHLOPDAN| { &m.FGCPMGKNMOK },
            |m: &mut KAKPHLOPDAN| { &mut m.FGCPMGKNMOK },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "IGDJLMDKHCJ",
            |m: &KAKPHLOPDAN| { &m.IGDJLMDKHCJ },
            |m: &mut KAKPHLOPDAN| { &mut m.IGDJLMDKHCJ },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "FILMAOEBILH",
            |m: &KAKPHLOPDAN| { &m.FILMAOEBILH },
            |m: &mut KAKPHLOPDAN| { &mut m.FILMAOEBILH },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "IFPEPCBOJKJ",
            |m: &KAKPHLOPDAN| { &m.IFPEPCBOJKJ },
            |m: &mut KAKPHLOPDAN| { &mut m.IFPEPCBOJKJ },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "ENEOHGOGJHO",
            |m: &KAKPHLOPDAN| { &m.ENEOHGOGJHO },
            |m: &mut KAKPHLOPDAN| { &mut m.ENEOHGOGJHO },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "PNNKEEFNNOI",
            |m: &KAKPHLOPDAN| { &m.PNNKEEFNNOI },
            |m: &mut KAKPHLOPDAN| { &mut m.PNNKEEFNNOI },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "CMCBBHJELBD",
            |m: &KAKPHLOPDAN| { &m.CMCBBHJELBD },
            |m: &mut KAKPHLOPDAN| { &mut m.CMCBBHJELBD },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<KAKPHLOPDAN>(
            "KAKPHLOPDAN",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for KAKPHLOPDAN {
    const NAME: &'static str = "KAKPHLOPDAN";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                80 => {
                    self.FJIOMCLFLMK = is.read_uint32()?;
                },
                72 => {
                    self.KCNBAPCDOAC = is.read_uint32()?;
                },
                66 => {
                    is.read_repeated_packed_uint32_into(&mut self.HPEHGIGBKFH)?;
                },
                64 => {
                    self.HPEHGIGBKFH.push(is.read_uint32()?);
                },
                26 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.IMKELKMHOIK)?;
                },
                40 => {
                    self.FGCPMGKNMOK = is.read_uint32()?;
                },
                56 => {
                    self.IGDJLMDKHCJ = is.read_uint32()?;
                },
                88 => {
                    self.FILMAOEBILH = is.read_uint32()?;
                },
                96 => {
                    self.IFPEPCBOJKJ = is.read_uint32()?;
                },
                120 => {
                    self.ENEOHGOGJHO = is.read_uint32()?;
                },
                16 => {
                    self.PNNKEEFNNOI = is.read_uint32()?;
                },
                104 => {
                    self.CMCBBHJELBD = is.read_enum_or_unknown()?;
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
        if self.FJIOMCLFLMK != 0 {
            my_size += ::protobuf::rt::uint32_size(10, self.FJIOMCLFLMK);
        }
        if self.KCNBAPCDOAC != 0 {
            my_size += ::protobuf::rt::uint32_size(9, self.KCNBAPCDOAC);
        }
        for value in &self.HPEHGIGBKFH {
            my_size += ::protobuf::rt::uint32_size(8, *value);
        };
        if let Some(v) = self.IMKELKMHOIK.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if self.FGCPMGKNMOK != 0 {
            my_size += ::protobuf::rt::uint32_size(5, self.FGCPMGKNMOK);
        }
        if self.IGDJLMDKHCJ != 0 {
            my_size += ::protobuf::rt::uint32_size(7, self.IGDJLMDKHCJ);
        }
        if self.FILMAOEBILH != 0 {
            my_size += ::protobuf::rt::uint32_size(11, self.FILMAOEBILH);
        }
        if self.IFPEPCBOJKJ != 0 {
            my_size += ::protobuf::rt::uint32_size(12, self.IFPEPCBOJKJ);
        }
        if self.ENEOHGOGJHO != 0 {
            my_size += ::protobuf::rt::uint32_size(15, self.ENEOHGOGJHO);
        }
        if self.PNNKEEFNNOI != 0 {
            my_size += ::protobuf::rt::uint32_size(2, self.PNNKEEFNNOI);
        }
        if self.CMCBBHJELBD != ::protobuf::EnumOrUnknown::new(super::BLBJBAMDNBN::BLBJBAMDNBN::MATCH3_PLAYER_STATE_ALIVE) {
            my_size += ::protobuf::rt::int32_size(13, self.CMCBBHJELBD.value());
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if self.FJIOMCLFLMK != 0 {
            os.write_uint32(10, self.FJIOMCLFLMK)?;
        }
        if self.KCNBAPCDOAC != 0 {
            os.write_uint32(9, self.KCNBAPCDOAC)?;
        }
        for v in &self.HPEHGIGBKFH {
            os.write_uint32(8, *v)?;
        };
        if let Some(v) = self.IMKELKMHOIK.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(3, v, os)?;
        }
        if self.FGCPMGKNMOK != 0 {
            os.write_uint32(5, self.FGCPMGKNMOK)?;
        }
        if self.IGDJLMDKHCJ != 0 {
            os.write_uint32(7, self.IGDJLMDKHCJ)?;
        }
        if self.FILMAOEBILH != 0 {
            os.write_uint32(11, self.FILMAOEBILH)?;
        }
        if self.IFPEPCBOJKJ != 0 {
            os.write_uint32(12, self.IFPEPCBOJKJ)?;
        }
        if self.ENEOHGOGJHO != 0 {
            os.write_uint32(15, self.ENEOHGOGJHO)?;
        }
        if self.PNNKEEFNNOI != 0 {
            os.write_uint32(2, self.PNNKEEFNNOI)?;
        }
        if self.CMCBBHJELBD != ::protobuf::EnumOrUnknown::new(super::BLBJBAMDNBN::BLBJBAMDNBN::MATCH3_PLAYER_STATE_ALIVE) {
            os.write_enum(13, ::protobuf::EnumOrUnknown::value(&self.CMCBBHJELBD))?;
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

    fn new() -> KAKPHLOPDAN {
        KAKPHLOPDAN::new()
    }

    fn clear(&mut self) {
        self.FJIOMCLFLMK = 0;
        self.KCNBAPCDOAC = 0;
        self.HPEHGIGBKFH.clear();
        self.IMKELKMHOIK.clear();
        self.FGCPMGKNMOK = 0;
        self.IGDJLMDKHCJ = 0;
        self.FILMAOEBILH = 0;
        self.IFPEPCBOJKJ = 0;
        self.ENEOHGOGJHO = 0;
        self.PNNKEEFNNOI = 0;
        self.CMCBBHJELBD = ::protobuf::EnumOrUnknown::new(super::BLBJBAMDNBN::BLBJBAMDNBN::MATCH3_PLAYER_STATE_ALIVE);
        self.special_fields.clear();
    }

    fn default_instance() -> &'static KAKPHLOPDAN {
        static instance: KAKPHLOPDAN = KAKPHLOPDAN {
            FJIOMCLFLMK: 0,
            KCNBAPCDOAC: 0,
            HPEHGIGBKFH: ::std::vec::Vec::new(),
            IMKELKMHOIK: ::protobuf::MessageField::none(),
            FGCPMGKNMOK: 0,
            IGDJLMDKHCJ: 0,
            FILMAOEBILH: 0,
            IFPEPCBOJKJ: 0,
            ENEOHGOGJHO: 0,
            PNNKEEFNNOI: 0,
            CMCBBHJELBD: ::protobuf::EnumOrUnknown::from_i32(0),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for KAKPHLOPDAN {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("KAKPHLOPDAN").unwrap()).clone()
    }
}

impl ::std::fmt::Display for KAKPHLOPDAN {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for KAKPHLOPDAN {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x11KAKPHLOPDAN.proto\x1a\x11BLBJBAMDNBN.proto\x1a\x11DHPIFKICOPP.prot\
    o\"\x9f\x03\n\x0bKAKPHLOPDAN\x12\x20\n\x0bFJIOMCLFLMK\x18\n\x20\x01(\rR\
    \x0bFJIOMCLFLMK\x12\x20\n\x0bKCNBAPCDOAC\x18\t\x20\x01(\rR\x0bKCNBAPCDOA\
    C\x12\x20\n\x0bHPEHGIGBKFH\x18\x08\x20\x03(\rR\x0bHPEHGIGBKFH\x12.\n\x0b\
    IMKELKMHOIK\x18\x03\x20\x01(\x0b2\x0c.DHPIFKICOPPR\x0bIMKELKMHOIK\x12\
    \x20\n\x0bFGCPMGKNMOK\x18\x05\x20\x01(\rR\x0bFGCPMGKNMOK\x12\x20\n\x0bIG\
    DJLMDKHCJ\x18\x07\x20\x01(\rR\x0bIGDJLMDKHCJ\x12\x20\n\x0bFILMAOEBILH\
    \x18\x0b\x20\x01(\rR\x0bFILMAOEBILH\x12\x20\n\x0bIFPEPCBOJKJ\x18\x0c\x20\
    \x01(\rR\x0bIFPEPCBOJKJ\x12\x20\n\x0bENEOHGOGJHO\x18\x0f\x20\x01(\rR\x0b\
    ENEOHGOGJHO\x12\x20\n\x0bPNNKEEFNNOI\x18\x02\x20\x01(\rR\x0bPNNKEEFNNOI\
    \x12.\n\x0bCMCBBHJELBD\x18\r\x20\x01(\x0e2\x0c.BLBJBAMDNBNR\x0bCMCBBHJEL\
    BDb\x06proto3\
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
            let mut deps = ::std::vec::Vec::with_capacity(2);
            deps.push(super::BLBJBAMDNBN::file_descriptor().clone());
            deps.push(super::DHPIFKICOPP::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(KAKPHLOPDAN::generated_message_descriptor_data());
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