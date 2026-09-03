"""The declarative codec: layout compilation, JSON dict form, name resolution."""

# Copyright (C) 2026 The c65sdn Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Attributes published by the codec are set at runtime, and the exact-type
# assertions below are deliberate: a subclass would defeat the point.
# pylint: disable=no-member,protected-access,unidiomatic-typecheck

import inspect

import pytest

import c65of.packet.icmp as icmp_v4
import c65of.packet.icmpv6 as icmp_v6
from c65of.codec import REQUIRED, Codec, TLVRegistry, msg_pack_into


class Sample(Codec):
    """Fixture with one of each declaration feature."""

    _FMT = "IH6x"
    _FIELDS = "port max_len"
    _EXTRA = "type len"
    _DEFAULTS = {"port": REQUIRED, "max_len": 65509}


class Hidden(Codec):
    """Fixture with a lead parameter kept out of the JSON dict form."""

    _LEAD = "datapath"
    _HIDDEN = "datapath"
    _FMT = "B"
    _FIELDS = "table_id"


class Ordered(Codec):
    """Fixture declaring its own attribute order."""

    _FMT = "BB"
    _FIELDS = "second first"
    _ATTRS = ("second", "first")


def test_generated_signature_matches_the_declaration():
    """Parameters follow _LEAD, then _FIELDS, then _EXTRA, with defaults."""
    params = inspect.signature(Sample.__init__).parameters
    assert list(params) == ["self", "port", "max_len", "type_", "len_"]
    assert params["port"].default is inspect.Parameter.empty
    assert params["max_len"].default == 65509
    assert params["type_"].default is None


def test_builtin_shadowing_parameters_are_mangled():
    """A parameter takes a trailing underscore; the attribute does not."""
    obj = Sample(port=1, type_=9, len_=16)
    assert (obj.type, obj.len) == (9, 16)
    with pytest.raises(TypeError):
        Sample(port=1, type=9)


def test_declared_attributes_are_published_on_the_class():
    """Defaults are visible without instantiating."""
    assert Sample.max_len == 65509
    assert Sample.port is None


def test_pack_and_unpack_round_trip():
    """The compiled struct packs and unpacks the declared fields."""
    obj = Sample(port=3)
    assert Sample.unpack_fixed(obj.pack_fixed()) == {"port": 3, "max_len": 65509}


def test_attrs_sorted_unless_declared():
    """Attribute order is alphabetical by default, declared order otherwise."""
    assert Sample._ATTRS == ("len", "max_len", "port", "type")
    assert Ordered._ATTRS == ("second", "first")


def test_hidden_attributes_stay_out_of_the_json_form():
    """A _HIDDEN attribute is set but never serialized."""
    obj = Hidden("a-datapath", table_id=2)
    assert obj.datapath == "a-datapath"
    assert obj.to_jsondict() == {"Hidden": {"table_id": 2}}


def test_bad_field_count_is_rejected_at_class_creation():
    """A _FIELDS list that does not match _FMT fails loudly."""
    with pytest.raises(TypeError, match="_FIELDS has"):

        class Broken(Codec):  # pylint: disable=unused-variable
            """Two names for a one value format."""

            _FMT = "B"
            _FIELDS = "one two"


def test_bytes_are_base64_in_the_json_form():
    """Opaque bytes survive a JSON round trip."""
    obj = Hidden(None, table_id=1)
    obj.table_id = b"\x00\xff"
    assert obj.to_jsondict()["Hidden"]["table_id"] == "AP8="


def test_obj_from_jsondict_rejects_multiple_keys():
    """A JSON dict naming more than one class is an error."""
    with pytest.raises(ValueError, match="single class name"):
        Codec.obj_from_jsondict({"Sample": {}, "Hidden": {}})


def test_nested_name_resolves_against_the_enclosing_module():
    """icmp and icmpv6 both define echo; each resolves to its own.

    The two have identical layouts, so a jsondict comparison cannot tell them
    apart -- only the resolved type can.
    """
    v6 = icmp_v6.icmpv6(type_=128, data=icmp_v6.echo(1, 2, b"hi"))
    assert (
        type(icmp_v6.icmpv6.from_jsondict(v6.to_jsondict()["icmpv6"]).data)
        is icmp_v6.echo
    )

    v4 = icmp_v4.icmp(type_=8, data=icmp_v4.echo(1, 2, b"hi"))
    assert (
        type(icmp_v4.icmp.from_jsondict(v4.to_jsondict()["icmp"]).data) is icmp_v4.echo
    )


def test_registry_keeps_the_first_claim_on_a_name():
    """A duplicate class name does not displace the first registration."""
    assert Codec.cls_from_jsondict_key("echo") in (icmp_v4.echo, icmp_v6.echo)
    assert icmp_v6.icmpv6.cls_from_jsondict_key("echo") is icmp_v6.echo


def test_tlv_registry_rejects_a_duplicate_type():
    """Two classes cannot claim one type id."""
    registry = TLVRegistry("thing")

    class First(Codec):
        """First claimant."""

        _TYPE_ID = 1

    class Second(Codec):
        """Second claimant of the same id."""

        _TYPE_ID = 1

    registry.register(First)
    assert registry.lookup(1) is First
    assert registry.lookup(2) is None
    with pytest.raises(TypeError, match="already registered"):
        registry.register(Second)


def test_msg_pack_into_grows_the_buffer():
    """Packing past the end extends rather than raising."""
    buf = bytearray()
    msg_pack_into("!I", buf, 4, 7)
    assert bytes(buf) == b"\x00\x00\x00\x00\x00\x00\x00\x07"
