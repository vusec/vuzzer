#include <algorithm>
#include <set>
#include <bm/bm.h>
#include <ewah.h>
#include <bitset>
#include <string>
#include <sstream>
#include <errno.h>
#include "pin.H"

#include "tag_traits.h"

/* *** Unsigned char based tags. ************************************/
template<>
unsigned char tag_combine(unsigned char const & lhs, unsigned char const & rhs) {
	return lhs | rhs;
}

template<>
void tag_combine_inplace(unsigned char & lhs, unsigned char const & rhs) {
	lhs |= rhs;
}

template<>
std::string tag_sprint(unsigned char const & tag) {
	return std::bitset<(sizeof(tag) << 3)>(tag).to_string();
}


/* *** set<uint32_t> based tags. ************************************/
/* define the set/cleared values */
const std::set<uint32_t> tag_traits<std::set<uint32_t>>::cleared_val = std::set<uint32_t>();
const std::set<uint32_t> tag_traits<std::set<uint32_t>>::set_val = std::set<uint32_t>{1};

template<>
std::set<uint32_t> tag_combine(std::set<uint32_t> const & lhs, std::set<uint32_t> const & rhs) {
	std::set<uint32_t> res;

	std::set_union(
			lhs.begin(), lhs.end(),
			rhs.begin(), rhs.end(),
			std::inserter(res, res.begin())
	);

	return res;
}

template<>
void tag_combine_inplace(std::set<uint32_t> & lhs, std::set<uint32_t> const & rhs) {
	lhs.insert(rhs.begin(), rhs.end());
}

template<>
std::string tag_sprint(std::set<uint32_t> const & tag) {
	std::set<uint32_t>::const_iterator t;
	std::stringstream ss;

	ss << "{";
	if (!tag.empty()) {
		std::set<uint32_t>::const_iterator last = std::prev(tag.end());
		for (t = tag.begin(); t != last; t++)
			ss << *t << ", ";
		ss << *(t++);
	}
	ss << "}";
	return ss.str();
}


/* *** set<fdoff_t> based tags. ************************************/
/* 
   define the set/cleared values
   the set_val is kind of arbitrary here - represents offset 0 of stdin
 */
const std::set<fdoff_t> tag_traits<std::set<fdoff_t>>::cleared_val = std::set<fdoff_t>();
const std::set<fdoff_t> tag_traits<std::set<fdoff_t>>::set_val = std::set<fdoff_t>{fdoff_t{0, 0}};

template<>
std::set<fdoff_t> tag_combine(std::set<fdoff_t> const & lhs, std::set<fdoff_t> const & rhs) {
	std::set<fdoff_t> res;

	std::set_union(
		lhs.begin(), lhs.end(),
		rhs.begin(), rhs.end(),
		std::inserter(res, res.begin())
	);

	return res;
}

template<>
void tag_combine_inplace(std::set<fdoff_t> & lhs, std::set<fdoff_t> const & rhs) {
	lhs.insert(rhs.begin(), rhs.end());
}

template<>
std::string tag_sprint(std::set<fdoff_t> const & tag) {
	std::set<fdoff_t>::const_iterator t;
	std::stringstream ss;

	ss << "{";
	if (!tag.empty()) {
		std::set<fdoff_t>::const_iterator last = std::prev(tag.end());
		for (t = tag.begin(); t != last; t++)
			ss << (*t).first << ":" << (*t).second << ", ";
		ss << (*t).first << ":" << (*t).second;
		t++;
	}
	ss << "}";
	return ss.str();
}

template<>
bool tag_count(std::set<fdoff_t> const & tag) {
	if(!tag.empty()){
		return 1;
	}else{
		return 0;
	}
}


/* *** bitset<> based tags. ****************************************/
/*
   define the set/cleared values
   the set_val is kind of arbitrary - represents all bits set
 */
const std::bitset<TAG_BITSET_SIZE> tag_traits<std::bitset<TAG_BITSET_SIZE>>::cleared_val = std::bitset<TAG_BITSET_SIZE>{};
const std::bitset<TAG_BITSET_SIZE> tag_traits<std::bitset<TAG_BITSET_SIZE>>::set_val = std::bitset<TAG_BITSET_SIZE>{}.set();

template<>
std::bitset<TAG_BITSET_SIZE> tag_combine(std::bitset<TAG_BITSET_SIZE> const & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs) {
	return lhs | rhs;
}

template<>
void tag_combine_inplace(std::bitset<TAG_BITSET_SIZE> & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs) {
	lhs |= rhs;
}

template<>
std::string tag_sprint(std::bitset<TAG_BITSET_SIZE> const & tag) {
	return tag.to_string();
}

template<>
bool tag_count(std::bitset<TAG_BITSET_SIZE> const & tag) {
	if(tag.count()){
		return 1;
	}else{
		return 0;
	}
}

/* *** EWAHBoolArray based tags. ****************************************/
/*
   define the set/cleared values
   the set_val is kind of arbitrary - will not be of much use. just set 1st bit.
 */
const EWAHBoolArray<uint32_t> tag_traits<EWAHBoolArray<uint32_t>>::cleared_val = EWAHBoolArray<uint32_t>{};
const EWAHBoolArray<uint32_t> tag_traits<EWAHBoolArray<uint32_t>>::set_val = EWAHBoolArray<uint32_t>{};

template<>
EWAHBoolArray<uint32_t> tag_combine(EWAHBoolArray<uint32_t> const & lhs, EWAHBoolArray<uint32_t> const & rhs) {
	EWAHBoolArray<uint32_t> result;
	lhs.logicalor(rhs, result);
	return result;
}

template<>
void tag_combine_inplace(EWAHBoolArray<uint32_t> & lhs, EWAHBoolArray<uint32_t> const & rhs) {
	EWAHBoolArray<uint32_t> result;
	lhs.logicalor(rhs, result);
	lhs = result;
}

template<>
std::string tag_sprint(EWAHBoolArray<uint32_t> const & tag) {
    std::stringstream ss;
    if(tag.numberOfOnes())
    	ss << tag;
    else
	return "{}";
    return ss.str();

}

template<>
bool tag_count(EWAHBoolArray<uint32_t> const & tag) {
	if(tag.numberOfOnes()){
		return 1;
	}else{
		return 0;
	}
}

/* *** bvector<> based tags. ****************************************/
/*
   define the set/cleared values
   the set_val is kind of arbitrary - will not be of much use. just set 1st bit.
 */

bm::bvector<> bq;
const bm::bvector<> tag_traits<bm::bvector<>>::cleared_val = bq;
const bm::bvector<> tag_traits<bm::bvector<>>::set_val = bq;

template<>
bm::bvector<> tag_combine(bm::bvector<> const & lhs, bm::bvector<> const & rhs) {
	return lhs | rhs;
}

template<>
void tag_combine_inplace(bm::bvector<> & lhs, bm::bvector<> const & rhs) {
	lhs |= rhs;
}

template<>
std::string tag_sprint(bm::bvector<> const & tag) {
    std::stringstream ss;
        ss << "{";
    	unsigned value = tag.get_first();
    	do
    	{
        	ss << value;
	        value = tag.get_next(value);
       		if (value)
        	{
            		ss << ",";
        	}
        	else
        	{
           		 break;
        	}
    	} while(1);
        ss << "}";

    return ss.str();

}

template<>
bool tag_count(bm::bvector<> const & tag) {
	if(tag.count())
		return 1;
	else
		return 0;
}
/* vim: set noet ts=4 sts=4 : */
