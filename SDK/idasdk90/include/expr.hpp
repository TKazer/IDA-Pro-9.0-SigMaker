/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _EXPR_H
#define _EXPR_H

#include <ieee.h>
#include <idp.hpp>

/*! \file expr.hpp

  \brief Functions that deal with C-like expressions and built-in IDC language.

  Functions marked #THREAD_SAFE may be called from any thread.
  No simultaneous calls should be made for the same variable.
  We protect only global structures, individual variables must
  be protected manually.
*/

//------------------------------------------------------------------------

// Forward declarations
class idc_value_t;
class idc_class_t;
class idc_object_t;

/// IDC script extension
#define IDC_LANG_EXT             "idc"

/// Convert IDC variable to a long (32/64bit) number.
/// \return v = 0 if impossible to convert to long

idaman THREAD_SAFE error_t ida_export idcv_long(idc_value_t *v);


/// Convert IDC variable to a 64bit number.
/// \return v = 0 if impossible to convert to int64

idaman THREAD_SAFE error_t ida_export idcv_int64(idc_value_t *v);


/// Convert IDC variable to a long number.
/// \return
///   - v = 0         if IDC variable = "false" string
///   - v = 1         if IDC variable = "true" string
///   - v = number    if IDC variable is number or string containing a number
///   - eTypeConflict if IDC variable = empty string

idaman THREAD_SAFE error_t ida_export idcv_num(idc_value_t *v);


/// Convert IDC variable to a text string

idaman THREAD_SAFE error_t ida_export idcv_string(idc_value_t *v);


/// Convert IDC variable to a floating point

idaman THREAD_SAFE error_t ida_export idcv_float(idc_value_t *v);


/// Create an IDC object. The original value of 'v' is discarded (freed).
/// \param v     variable to hold the object. any previous value will be cleaned
/// \param icls  ptr to the desired class. nullptr means "object" class
///              this ptr must be returned by add_idc_class() or find_idc_class()
/// \return always eOk

idaman THREAD_SAFE error_t ida_export idcv_object(
        idc_value_t *v,
        const idc_class_t *icls=nullptr);


/// Move 'src' to 'dst'.
/// This function is more effective than copy_idcv since it never copies big
/// amounts of data.

idaman THREAD_SAFE error_t ida_export move_idcv(
        idc_value_t *dst,
        idc_value_t *src);


/// Copy 'src' to 'dst'.
/// For idc objects only a reference is copied.

idaman THREAD_SAFE error_t ida_export copy_idcv(
        idc_value_t *dst,
        const idc_value_t &src);


/// Deep copy an IDC object.
/// This function performs deep copy of idc objects.
/// If 'src' is not an object, copy_idcv() will be called

idaman THREAD_SAFE error_t ida_export deep_copy_idcv(
        idc_value_t *dst,
        const idc_value_t &src);


/// Free storage used by #VT_STR/#VT_OBJ IDC variables.
/// After this call the variable has a numeric value 0

idaman THREAD_SAFE void ida_export free_idcv(idc_value_t *v);


/// Swap 2 variables

idaman THREAD_SAFE void ida_export swap_idcvs(
        idc_value_t *v1,
        idc_value_t *v2);


/// Retrieves the IDC object class name.
/// \param out   qstring ptr for the class name. Can be nullptr.
/// \param obj   class instance variable
/// \return error code, eOk on success

idaman THREAD_SAFE error_t ida_export get_idcv_class_name(
        qstring *out,
        const idc_value_t *obj);


/// Get an object attribute.
/// \param res              buffer for the attribute value
/// \param obj              variable that holds an object reference.
///                         if obj is nullptr it searches global variables, then user functions
/// \param attr             attribute name
/// \param may_use_getattr  may call getattr functions to calculate the attribute if it does not exist
/// \return error code, eOk on success

idaman THREAD_SAFE error_t ida_export get_idcv_attr(
        idc_value_t *res,
        const idc_value_t *obj,
        const char *attr,
        bool may_use_getattr=false);


/// Set an object attribute.
/// \param obj              variable that holds an object reference.
///                         if obj is nullptr then it tries to modify a global variable with the attribute name
/// \param attr             attribute name
/// \param value            new attribute value
/// \param may_use_setattr  may call setattr functions for the class
/// \return error code, eOk on success

idaman THREAD_SAFE error_t ida_export set_idcv_attr(
        idc_value_t *obj,
        const char *attr,
        const idc_value_t &value,
        bool may_use_setattr=false);


/// Delete an object attribute.
/// \param obj   variable that holds an object reference
/// \param attr  attribute name
/// \return error code, eOk on success

idaman THREAD_SAFE error_t ida_export del_idcv_attr(
        idc_value_t *obj,
        const char *attr);


/// \name Enumerate object attributes
///@{
idaman THREAD_SAFE const char *ida_export first_idcv_attr(const idc_value_t *obj);
idaman THREAD_SAFE const char *ida_export last_idcv_attr(const idc_value_t *obj);
idaman THREAD_SAFE const char *ida_export next_idcv_attr(const idc_value_t *obj, const char *attr);
idaman THREAD_SAFE const char *ida_export prev_idcv_attr(const idc_value_t *obj, const char *attr);
///@}


/// Get text representation of idc_value_t

idaman bool ida_export print_idcv(
        qstring *out,
        const idc_value_t &v,
        const char *name=nullptr,
        int indent=0);


/// Get slice.
/// \param res    output variable that will contain the slice
/// \param v      input variable (string or object)
/// \param i1     slice start index
/// \param i2     slice end index (excluded)
/// \param flags  \ref VARSLICE_ or 0
/// \returns eOk if success

idaman THREAD_SAFE error_t ida_export get_idcv_slice(
        idc_value_t *res,
        const idc_value_t *v,
        uval_t i1,
        uval_t i2,
        int flags=0);

/// \defgroup VARSLICE_ IDC variable slice flags
/// Passed as 'flags' parameter to get_idcv_slice() and set_idcv_slice()
///@{
#define VARSLICE_SINGLE 0x0001  ///< return single index (i2 is ignored)
///@}

/// Set slice.
/// \param v      variable to modify (string or object)
/// \param i1     slice start index
/// \param i2     slice end index (excluded)
/// \param in     new value for the slice
/// \param flags  \ref VARSLICE_ or 0
/// \return eOk on success

idaman THREAD_SAFE error_t ida_export set_idcv_slice(
        idc_value_t *v,
        uval_t i1,
        uval_t i2,
        const idc_value_t &in,
        int flags=0);


//-------------------------------------------------------------------------
// IDC class related functions

/// Create a new IDC class.
/// \param name   name of the new class
/// \param super  the base class for the new class. if the new class is not based
///               on any other class, pass nullptr
/// \return pointer to the created class. If such a class already exists, a pointer
/// to it will be returned.
/// Pointers to other existing classes may be invalidated by this call.

idaman THREAD_SAFE idc_class_t *ida_export add_idc_class(
        const char *name,
        const idc_class_t *super=nullptr);


/// Find an existing IDC class by its name.
/// \param name  name of the class
/// \return pointer to the class or nullptr.
/// The returned pointer is valid until a new call to add_idc_class()

idaman THREAD_SAFE idc_class_t *ida_export find_idc_class(const char *name);


/// Set an IDC class method.
/// \param icls          pointer to the class
/// \param fullfuncname  name of the function to call. use full method name: classname.funcname
/// \retval true   success
/// \retval false  the function could not be found

idaman THREAD_SAFE bool ida_export set_idc_method(idc_class_t *icls, const char *fullfuncname);


/// \name Set user-defined functions to work with object attributes.
/// If the function name is nullptr, the definitions are removed.
/// \return name of the old attribute function. nullptr means error, "" means no previous attr func
///@{
idaman THREAD_SAFE const char *ida_export set_idc_getattr(idc_class_t *icls, const char *fullfuncname);
idaman THREAD_SAFE const char *ida_export set_idc_setattr(idc_class_t *icls, const char *fullfuncname);
///@}

/// Set a destructor for an idc class.
/// The destructor is called before deleting any object of the specified class.
/// Exceptions that escape the destructor are silently ignored, runtime errors too.

idaman THREAD_SAFE const char *ida_export set_idc_dtor(idc_class_t *icls, const char *fullfuncname);


/// Dereference a #VT_REF variable.
/// \param v           variable to dereference
/// \param vref_flags  \ref VREF_
/// \return pointer to the dereference result or nullptr.
/// If returns nullptr, qerrno is set to eExecBadRef "Illegal variable reference"

idaman THREAD_SAFE idc_value_t *ida_export deref_idcv(idc_value_t *v, int vref_flags);

/// \defgroup VREF_ Dereference IDC variable flags
/// Passed as 'vref_flags' parameter to deref_idcv()
///@{
#define VREF_LOOP 0x0000        ///< dereference until we get a non #VT_REF
#define VREF_ONCE 0x0001        ///< dereference only once, do not loop
#define VREF_COPY 0x0002        ///< copy the result to the input var (v)
///@}


/// Create a variable reference.
/// Currently only references to global variables can be created.
/// \param ref  ptr to the result
/// \param v    variable to reference
/// \return success

idaman THREAD_SAFE bool ida_export create_idcv_ref(idc_value_t *ref, const idc_value_t *v);


/// Add global IDC variable.
/// \param name  name of the global variable
/// \return pointer to the created variable or existing variable.
/// NB: the returned pointer is valid until a new global var is added.

idaman THREAD_SAFE idc_value_t *ida_export add_idc_gvar(const char *name);


/// Find an existing global IDC variable by its name.
/// \param name  name of the global variable
/// \return pointer to the variable or nullptr.
/// NB: the returned pointer is valid until a new global var is added.
/// FIXME: it is difficult to use this function in a thread safe manner

idaman THREAD_SAFE idc_value_t *ida_export find_idc_gvar(const char *name);


//-------------------------------------------------------------------------
/// Class to hold idc values
class idc_value_t
{
public:
/// \defgroup VT_ IDC value types
/// Used by idc_value_t::vtype
///@{
#define  VT_LONG        2       ///< Integer (see idc_value_t::num)
#define  VT_FLOAT       3       ///< Floating point (see idc_value_t::e)
#define  VT_WILD        4       ///< Function with arbitrary number of arguments.
                                ///< The actual number of arguments will be passed in idc_value_t::num.
                                ///< This value should not be used for ::idc_value_t.
#define  VT_OBJ         5       ///< Object (see idc_value_t::obj)
#define  VT_FUNC        6       ///< Function (see idc_value_t::funcidx)
#define  VT_STR         7       ///< String (see qstr() and similar functions)
#define  VT_PVOID       8       ///< void *
#define  VT_INT64       9       ///< i64
#define  VT_REF        10       ///< Reference
///@}
  char vtype = VT_LONG;         ///< \ref VT_

#ifndef SWIG
  // this union must be the last member (see memset below)
  union
  {
#endif // SWIG
    sval_t num;                 ///< #VT_LONG
    fpvalue_t e;                ///< #VT_FLOAT
    idc_object_t *obj;
    int funcidx;                ///< #VT_FUNC
    void *pvoid;                ///< #VT_PVOID
    int64 i64;                  ///< #VT_INT64
    uchar reserve[sizeof(qstring)]; ///< VT_STR
#ifndef SWIG
  };
#endif // SWIG

  /// Create a #VT_LONG value
  idc_value_t(sval_t n=0)
  {
    memset(reserve, 0, sizeof(idc_value_t) - qoffsetof(idc_value_t, reserve));
    num = n;
  }
  /// Create a $VT_LONG with an existing idc value
  idc_value_t(const idc_value_t &r)
  {
    memset(reserve, 0, sizeof(idc_value_t) - qoffsetof(idc_value_t, reserve));
    copy_idcv(this, r);
  }
  /// Create a #VT_STR value
  idc_value_t(const char *_str) : vtype(VT_STR) { new(&qstr()) qstring(_str); }
  /// Create a #VT_STR value
  idc_value_t(const qstring &_str) : vtype(VT_STR) { new(&qstr()) qstring(_str); }
  /// Destructor
  ~idc_value_t(void) { clear(); }
  /// See free_idcv()
  void clear(void) { free_idcv(this); } // put num 0
  /// Assign this value to an existing value
  idc_value_t &operator = (const idc_value_t &r)
  {
    copy_idcv(this, r);
    return *this;
  }
        qstring &qstr(void)       { return *(qstring *)&num; }       ///< #VT_STR
  const qstring &qstr(void) const { return *(qstring *)&num; }       ///< #VT_STR
  const char *c_str(void) const   { return qstr().c_str(); }         ///< #VT_STR
  const uchar *u_str(void) const  { return (const uchar *)c_str(); } ///< #VT_STR
  void swap(idc_value_t &v) { swap_idcvs(this, &v); }                   ///< Set this = r and v = this
  bool is_zero(void) const { return vtype == VT_LONG && num == 0; }  ///< Does value represent the integer 0?
  bool is_integral(void)   { return vtype == VT_LONG || vtype == VT_INT64; } ///< Does value represent a whole number?
  /// Convertible types are #VT_LONG, #VT_FLOAT, #VT_INT64, and #VT_STR
  bool is_convertible(void) const { return (vtype >= 1 && vtype <= VT_FLOAT) || vtype == VT_STR || vtype == VT_INT64; }

  /// \name Warning
  /// The following functions do not free the existing data!
  /// When the contents are unknown, use the functions without a leading underscore.
  ///@{
  void _create_empty_string(void) { vtype = VT_STR; new (&qstr()) qstring; }
  void _set_string(const qstring &_str)
  {
    vtype = VT_STR;
    new (&qstr()) qstring(_str);
  }
  void _set_string(const char *_str, size_t len)
  {
    vtype = VT_STR;
    new (&qstr()) qstring(_str, len);
  }
  void _set_string(const char *_str)
  {
    size_t len = _str == nullptr ? 0 : strlen(_str);
    _set_string(_str, len);
  }
  void _set_long(sval_t v) { vtype = VT_LONG; num = v; }
  void _set_pvoid(void *p) { vtype = VT_PVOID; pvoid = p; }
  void _set_int64(int64 v) { vtype = VT_INT64; i64 = v; }
  void _set_float(const fpvalue_t &f) { vtype = VT_FLOAT; e = f; }
  ///@}

  /// \name Setters
  /// These functions ensure the previous value is cleared
  ///@{
  void create_empty_string(void) { clear(); _create_empty_string(); }
  void set_string(const char *_str, size_t len) { clear(); _set_string(_str, len); }
  void set_string(const char *_str) { clear(); _set_string(_str); }
  void set_string(const qstring &_str) { clear(); _set_string(_str); }
  void set_long(sval_t v) { clear(); _set_long(v); }
  void set_pvoid(void *p) { clear(); vtype = VT_PVOID; pvoid = p; }
  void set_int64(int64 v) { clear(); vtype = VT_INT64; i64 = v; }
  void set_float(const fpvalue_t &f) { clear(); vtype = VT_FLOAT; e = f; }
  ///@}
};

/// Global idc variable
struct idc_global_t
{
  qstring name;
  idc_value_t value;
  idc_global_t(void) {}
  idc_global_t(const char *n) : name(n) {}
};
typedef qvector<idc_global_t> idc_vars_t; ///< vector of global idc variables

/// Prototype of an external IDC function (implemented in C).
/// \param argv  vector of input arguments. IDA will convert all arguments
///              to types specified by ext_idcfunc_t::args, except for #VT_WILD
/// \param r     return value of the function or exception
/// \return 0 if ok, all other values indicate error.
///         the error code must be set with set_qerrno():
///         - #eExecThrow - a new exception has been generated, see 'r'
///         - other values - runtime error has occurred

typedef error_t idaapi idc_func_t(idc_value_t *argv, idc_value_t *r);

#define eExecThrow 90           ///< See return value of ::idc_func_t

/// Element of functions table. See idcfuncs_t::funcs
struct ext_idcfunc_t
{
  const char *name;             ///< Name of function
  idc_func_t *fptr;             ///< Pointer to the Function
  const char *args;             ///< Type of arguments. Terminated with 0.
                                ///< #VT_WILD at the end means a variadic function.
                                ///< Actual number of arguments will be passed
                                ///< in res->num in this case.
  const idc_value_t *defvals;   ///< Default argument values.
                                ///< Only the rightmost arguments may have
                                ///< default values.
  int ndefvals;                 ///< Number of default values.
  int flags;                    ///< \ref EXTFUN_
/// \defgroup EXTFUN_ Function description flags
/// Used by ext_idcfunc_t::flags
///@{
#define EXTFUN_BASE  0x0001     ///< requires open database.
#define EXTFUN_NORET 0x0002     ///< does not return. the interpreter may
                                ///< clean up its state before calling it.
#define EXTFUN_SAFE  0x0004     ///< thread safe function. may be called
                                ///< from any thread.
///@}
};

/// Describes an array of IDC functions
struct idcfuncs_t
{
  size_t qnty;                  ///< Number of functions
  ext_idcfunc_t *funcs;         ///< Function table

  /// \name IDC Engine
  /// IDC engine requires the following functions (all of them may be nullptr)
  ///@{

  /// Start IDC engine. Called before executing any IDC code.
  error_t (idaapi *startup)(void);

  /// Stop IDC engine. Called when all IDC engines finish.
  /// In other words, nested IDC engines do not call startup/shutdown.
  error_t (idaapi *shutdown)(void);

  /// Initialize IDC engine. Called once at the very beginning of work.
  /// This callback may create additional IDC classes, methods, etc.
  void (idaapi *init_idc)(void);

  /// Terminate IDC engine. Called once at the very end of work.
  void (idaapi *term_idc)(void);

  /// Is the database open? (used for #EXTFUN_BASE functions).
  /// if this pointer is nullptr, #EXTFUN_BASE is not checked.
  bool (idaapi *is_database_open)(void);

  /// Convert an address to a string.
  /// if this pointer is nullptr, '%a' will be used.
  size_t (idaapi *ea2str)(char *buf, size_t bufsize, ea_t ea);

  /// Should a variable name be accepted without declaration?.
  /// When the parser encounters an unrecognized variable, this callback is called.
  /// If it returns false, the parser generates the 'undefined variable' error
  /// else the parser generates code to call to a set or get function,
  /// depending on the current context.
  /// If this pointer is nullptr, undeclared variables won't be supported.
  /// However, if 'resolver' object is provided to the parser, it will be used
  /// to resolve such names to constants at the compilation time.
  /// This callback is used by IDA to handle processor register names.
  bool (idaapi *undeclared_variable_ok)(const char *name);

  ///@}

  /// \name Indexes
  /// Indexes into the 'f' array. non-positive values mean that the function does not exist
  ///@{

  /// Retrieve value of an undeclared variable.
  /// Expected prototype: get(#VT_STR varname)
  int get_unkvar;

  /// Store a value to an undeclared variable.
  /// Expected prototype: set(#VT_WILD new_value, #VT_STR varname)
  int set_unkvar;

  /// Execute resolved function.
  /// If 'resolver' was used to resolve an unknown name to a constant in a function
  /// call context, such a call will be redirected here.
  /// Expected prototype: exec_resolved_func(#VT_LONG func, #VT_WILD typeinfo, ...)
  /// This callback is used in IDA for Appcall.
  int exec_resolved_func;

  /// Calculate sizeof(type).
  /// This function is used by the interpreter to calculate sizeof() expressions.
  /// Please note that the 'type' argument is an IDC object of typeinfo class.
  /// Expected prototype: calc_sizeof(#VT_OBJ typeinfo)
  /// This callback requires support of the type system (available only in IDA kernel)
  /// It should not be used by standalone IDC interpreters.
  int calc_sizeof;

  /// Get address of the specified field using the type information from the idb.
  /// This function is used to resolve expressions like 'mystr.field' where
  /// mystr does not represent an IDC object but just a plain number.
  /// The number is interpreted as an address in the current idb.
  /// This function retrieves type information at this address and tried to find
  /// the specified 'field'. It returns the address of the 'field' in the idb.
  /// This callback should not be used by standalone IDC interpreters.
  int get_field_ea;

  ///@}
};

// Our idc_value_t and idc_global_t classes are freely movable with memcpy()
DECLARE_TYPE_AS_MOVABLE(idc_value_t);
DECLARE_TYPE_AS_MOVABLE(idc_global_t);

//------------------------------------------------------------------------
/// Add an IDC function.
/// This function does not modify the predefined kernel functions.
/// Example:
/// \code
///  static error_t idaapi myfunc5(idc_value_t *argv, idc_value_t *res)
///  {
///    msg("myfunc is called with arg0=%a and arg1=%s\n", argv[0].num, argv[1].str);
///    res->num = 5;     // let's return 5
///    return eOk;
///  }
///  static const char myfunc5_args[] = { VT_LONG, VT_STR, 0 };
///  static const ext_idcfunc_t myfunc_desc = { "MyFunc5", myfunc5, myfunc5_args, nullptr, 0, EXTFUN_BASE };
///
///  // after this:
///  add_idc_func(myfunc_desc);
///
///  // there is a new IDC function which can be called like this:
///  MyFunc5(0x123, "test");
///
/// \endcode
/// \param func function description block.
/// \note If the function already exists, it will be replaced by the new function
/// \return success

idaman THREAD_SAFE bool ida_export add_idc_func(const ext_idcfunc_t &func);


/// Delete an IDC function
///
idaman THREAD_SAFE bool ida_export del_idc_func(const char *name);


// Find an idc function that starts with the given prefix.
// \param out    buffer for the output name
// \param prefix prefix to search for
// \param n      how many matches to skip
// Returns: success
idaman THREAD_SAFE bool ida_export find_idc_func(
        qstring *out,
        const char *prefix,
        int n=0);


/// Possible syntax element highlighting style names
enum syntax_highlight_style
{
  HF_DEFAULT = 0,
  HF_KEYWORD1 = 1,
  HF_KEYWORD2 = 2,
  HF_KEYWORD3 = 3,
  HF_STRING = 4,
  HF_COMMENT = 5,
  HF_PREPROC = 6,
  HF_NUMBER = 7,

  HF_MAX,
};
#define HF_FIRST HF_KEYWORD1

struct highlighter_cbs_t
{
  virtual ~highlighter_cbs_t() {}
  virtual void idaapi set_style(int32 /*start*/, int32 /*len*/, syntax_highlight_style /*style*/) {}
  virtual int32 idaapi prev_block_state() { return 0; }
  virtual int32 idaapi cur_block_state() { return 0; }
  virtual void idaapi set_block_state(int32 /*state*/) {}
};

/// Base class for syntax highligters
struct syntax_highlighter_t
{
  /// Function for extlang syntax highlighting
  /// \param context         implementation specific context. can be nullptr
  /// \param ighlighter_cbs  structure with set of callbacks
  /// \param text            part of text to colorize
  typedef void idaapi block_highlighter_t(
        void *context,
        highlighter_cbs_t *highlighter_cbs,
        const qstring &text);
  syntax_highlighter_t(block_highlighter_t *bh=nullptr) : highlight_block(bh) {}
  virtual ~syntax_highlighter_t() {}
  block_highlighter_t *highlight_block;
};


//------------------------------------------------------------------------
/// External language (to support third party language interpreters)
struct extlang_t
{
  size_t size;                  ///< Size of this structure
  uint32 flags;                 ///< Language features
#define EXTLANG_IDC 0x01
#define EXTLANG_NS_AWARE 0x02   ///< Namespace-aware (see above.)
  int32 refcnt;                 ///< Reference count
  const char *name;             ///< Language name
  const char *fileext;          ///< File name extension for the language
  syntax_highlighter_t *highlighter; // Language syntax highlighter

  /// Compile an expression.
  /// \param name         name of the function which will
  ///                     hold the compiled expression
  /// \param current_ea   current address. if unknown then #BADADDR
  /// \param expr         expression to compile
  /// \param[out] errbuf  error message if compilation fails
  /// \return success
  bool (idaapi *compile_expr)(
        const char *name,
        ea_t current_ea,
        const char *expr,
        qstring *errbuf);

  /// Compile (load) a file.
  ///
  /// If an extlang_t object claims to be namespace-aware, it means its
  /// 'compile_file()' will receive a requested namespace to compile a file
  /// under.
  ///
  /// For example, compile_file() might receive a file
  ///  '.../loaders/myloader.py', with the corresponding namespace:
  ///   '__loaders__myloader'
  ///
  /// Accordingly, call_func() has to be prepared to receive a function name that
  /// is namespace-qualified: "__loaders__myloader.accept_file()".
  ///
  /// \param file                 file name
  /// \param requested_namespace  requested namespace, may be ignored if not namespace-aware
  /// \param[out] errbuf          error message if compilation fails
  bool (idaapi *compile_file)(const char *file, const char *requested_namespace, qstring *errbuf);

  /// Evaluate a previously compiled expression.
  /// \param[out] result  function result or exception
  /// \param name         function to call
  /// \param nargs        number of input arguments
  /// \param args         input arguments
  /// \param[out] errbuf  error message if evaluation fails
  /// \return success
  bool (idaapi *call_func)(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf);

  /// Compile and evaluate an expression.
  /// \param[out] rv      expression value or exception
  /// \param current_ea   current address. if unknown then BADADDR
  /// \param expr         expression to evaluate
  /// \param[out] errbuf  error message if evaluation fails
  /// \return success
  bool (idaapi *eval_expr)(
        idc_value_t *rv,
        ea_t current_ea,
        const char *expr,
        qstring *errbuf);

  /// Compile and execute a string with statements.
  /// (see also: eval_expr() which works with expressions)
  /// \param str          input string to execute
  /// \param[out] errbuf  error message
  /// \return success
  bool (idaapi *eval_snippet)(
        const char *str,
        qstring *errbuf);

  /// Create an object instance.
  /// \param result      created object or exception
  /// \param name        object class name
  /// \param args        input arguments
  /// \param nargs       number of input arguments
  /// \param errbuf      error message if evaluation fails
  /// \return success
  bool (idaapi *create_object)(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf);

  /// Returns the attribute value of a given object from the global scope.
  /// \param[out] result  attribute value
  /// \param obj          object (may be nullptr)
  /// \param attr         attribute name.
  ///                     if nullptr or empty string then the object instance name
  ///                     (i.e. class name) should be returned.
  /// \return success
  bool (idaapi *get_attr)(
        idc_value_t *result,
        const idc_value_t *obj,
        const char *attr);

  /// Sets the attribute value of a given object in the global scope.
  /// \param obj    object (may be nullptr)
  /// \param attr   attribute name
  /// \param value  attribute value
  /// \return success
  bool (idaapi *set_attr)(
        idc_value_t *obj,
        const char *attr,
        const idc_value_t &value);

  /// Calls a member function.
  /// \param[out] result  function result or exception
  /// \param obj          object instance
  /// \param name         method name to call
  /// \param args         input arguments
  /// \param nargs        number of input arguments
  /// \param[out] errbuf  error message if evaluation fails
  /// \return success
  bool (idaapi *call_method)(
        idc_value_t *result,
        const idc_value_t *obj,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf);

  /// Compile (load) a file with processor module.
  ///
  /// See the note about namespace-awareness in compile_file()
  ///
  /// \param[out] procobj  created object or exception
  /// \param path          processor module file name
  /// \param[out] errbuf   error message if compilation fails
  /// \retval true   success
  /// \retval false  if errbuf is empty then file has been
  ///                 loaded (compiled) successfully but
  ///                it doesn't contain processor module
  bool (idaapi *load_procmod)(
        idc_value_t *procobj,
        const char *path,
        qstring *errbuf);

  /// Unload previously loaded processor module.
  /// \param path          processor module file name
  /// \param[out] errbuff  error message if compilation fails
  /// \return success
  bool (idaapi *unload_procmod)(
        const char *path,
        qstring *errbuf);

  bool is_idc(void) const { return (flags & EXTLANG_IDC) != 0; }
  bool is_namespace_aware(void) const { return (flags & EXTLANG_NS_AWARE) != 0; }
  void release(void) {}
};

typedef qvector<extlang_t *> extlangs_t; ///< vector of external language descriptions
typedef qrefcnt_t<extlang_t> extlang_object_t;

/// Get current active external language.

idaman void *ida_export get_current_extlang(void); // do not use

inline const extlang_object_t get_extlang(void)    // use this function
{
  return extlang_object_t((extlang_t *)get_current_extlang());
}


/// Install an external language interpreter.
/// Any previously registered interpreter will be automatically unregistered.
/// The installed extlang can be used in select_extlang().
/// \param el  description of the new language. must point to static storage.
/// \return extlang id; -1 means failure and will happen if the extlang has
///         already been installed

idaman ssize_t ida_export install_extlang(extlang_t *el);


/// Uninstall an external language interpreter.
/// \return success

idaman bool ida_export remove_extlang(extlang_t *el);


/// Selects the external language interpreter.
/// The specified extlang must be registered before selecting it.
/// It will be used to evaluate expressions entered in dialog boxes.
/// It will also replace the eval_expr() and eval_expr_long() functions.
/// \return success

idaman bool ida_export select_extlang(extlang_t *el);


struct extlang_visitor_t
{
  virtual ssize_t idaapi visit_extlang(extlang_t *extlang) = 0;
};

/// Process all registered extlangs
// \param ev     visitor object
// \param select temporarily select extlang for the duration of the visit
// \return 0 or the first non-zero value returned by visit_extlang()

idaman ssize_t ida_export for_all_extlangs(extlang_visitor_t &ev, bool select=false);


// Helper function to search for extlang
enum find_extlang_kind_t
{
  FIND_EXTLANG_BY_EXT,
  FIND_EXTLANG_BY_NAME,
  FIND_EXTLANG_BY_IDX,
};

// do not use
idaman void *ida_export find_extlang(const void *str, find_extlang_kind_t kind);


/// Get the extlang that can handle the given file extension

inline extlang_object_t find_extlang_by_ext(const char *ext)
{
  return extlang_object_t((extlang_t *)find_extlang(ext, FIND_EXTLANG_BY_EXT));
}

/// Find an extlang by name

inline extlang_object_t find_extlang_by_name(const char *name)
{
  return extlang_object_t((extlang_t *)find_extlang(name, FIND_EXTLANG_BY_NAME));
}

/// Find an extlang by index

inline extlang_object_t find_extlang_by_index(size_t idx)
{
  return extlang_object_t((extlang_t *)find_extlang(&idx, FIND_EXTLANG_BY_IDX));
}



//------------------------------------------------------------------------
/// Set or append a header path.
/// IDA looks for the include files in the appended header paths,
/// then in the ida executable directory.
/// \param path  list of directories to add (separated by ';')
///              may be nullptr, in this case nothing is added
/// \param add   true: append.
///              false: remove old paths.
/// \retval true   success
/// \retval false  no memory

idaman THREAD_SAFE bool ida_export set_header_path(const char *path, bool add);


/// Get full name of IDC file name.
/// Search for file in list of include directories, IDCPATH directory
/// and system directories.
/// \param buf      buffer for the answer
/// \param bufsize  size of buffer
/// \param file     file name without full path
/// \return nullptr is file not found.
///          otherwise returns pointer to buf

idaman THREAD_SAFE char *ida_export get_idc_filename(
        char *buf,
        size_t bufsize,
        const char *file);


/// Compile and execute "main" function from system file.
/// \param file  file name with IDC function(s).
///              The file will be searched using get_idc_filename().
/// \param complain_if_no_file
///              - 1: display warning if the file is not found
///              - 0: don't complain if file doesn't exist
/// \retval 1  ok, file is compiled and executed
/// \retval 0  failure, compilation or execution error, warning is displayed

idaman THREAD_SAFE bool ida_export exec_system_script(
        const char *file,
        bool complain_if_no_file=true);


/// Compile and calculate an expression.
/// \param res          pointer to result. The result will be converted
///                     to 32/64bit number. Use eval_expr() if you
///                     need the result of another type.
/// \param where        the current linear address in the addressing space of the
///                     program being disassembled. it will be used to resolve
///                     names of local variables, etc.
///                     if not applicable, then should be #BADADDR
/// \param line         a text line with IDC expression
/// \param[out] errbuf  buffer for the error message
/// \retval true   ok
/// \retval false  error, see errbuf

idaman bool ida_export eval_expr_long(
        sval_t *res,
        ea_t where,
        const char *line,
        qstring *errbuf=nullptr);

/// See eval_expr_long()

inline bool idaapi eval_expr_long(
        uval_t *res,
        ea_t where,
        const char *line,
        qstring *errbuf=nullptr)
{
  return eval_expr_long((sval_t *)res, where, line, errbuf);
}


/// Compile and calculate an expression.
/// \param rv           pointer to the result
/// \param where        the current linear address in the addressing space of the
///                     program being disassembled. If will be used to resolve
///                     names of local variables etc.
///                     if not applicable, then should be #BADADDR.
/// \param line         the expression to evaluate
/// \param[out] errbuf  buffer for the error message
/// \retval true   ok
/// \retval false  error, see errbuf

idaman bool ida_export eval_expr(
        idc_value_t *rv,
        ea_t where,
        const char *line,
        qstring *errbuf=nullptr);


/// Same as eval_expr(), but will always use the IDC interpreter regardless of the
/// currently installed extlang.

idaman bool ida_export eval_idc_expr(
        idc_value_t *rv,
        ea_t where,
        const char *buf,
        qstring *errbuf=nullptr);


/// Compile a text file with IDC function(s).
/// \param file         name of file to compile
///                     if nullptr, then "File not found" is returned.
/// \param[out] errbuf  buffer for the error message
/// \param cpl_flags    \ref CPL_ or 0
/// \retval true   ok
/// \retval false  error, see errbuf

/// \defgroup CPL_ Flags for compile_idc_file()
///@{
#define CPL_DEL_MACROS 0x0001  ///< delete macros at the end of compilation
#define CPL_USE_LABELS 0x0002  ///< allow program labels in the script
#define CPL_ONLY_SAFE  0x0004  ///< allow calls of only thread-safe functions
///@}

idaman THREAD_SAFE bool ida_export compile_idc_file(
        const char *file,
        qstring *errbuf=nullptr,
        int cpl_flags = CPL_DEL_MACROS|CPL_USE_LABELS);


/// Compile text with IDC function(s).
/// \param line             line with IDC function(s) (can't be nullptr!)
/// \param[out] errbuf      buffer for the error message
/// \param resolver         callback object to get values of undefined variables
///                         This object will be called if IDC function contains
///                         references to undefined variables. May be nullptr.
/// \param only_safe_funcs  if true, any calls to functions without #EXTFUN_SAFE flag
///                         will lead to a compilation error.
/// \retval true   ok
/// \retval false  error, see errbuf

struct idc_resolver_t
{
  virtual uval_t idaapi resolve_name(const char *name) = 0;
};

idaman THREAD_SAFE bool ida_export compile_idc_text(
        const char *line,
        qstring *errbuf=nullptr,
        idc_resolver_t *resolver=nullptr,
        bool only_safe_funcs=false);


/// Compile text with IDC statements.
/// \param func             name of the function to create out of the snippet
/// \param text             text to compile
/// \param[out] errbuf      buffer for the error message
/// \param resolver         callback object to get values of undefined variables
///                         This object will be called if IDC function contains
///                         references to undefined variables. May be nullptr.
/// \param only_safe_funcs  if true, any calls to functions without #EXTFUN_SAFE flag
///                         will lead to a compilation error.
/// \retval true   ok
/// \retval false  error, see errbuf

idaman bool ida_export compile_idc_snippet(
        const char *func,
        const char *text,
        qstring *errbuf=nullptr,
        idc_resolver_t *resolver=nullptr,
        bool only_safe_funcs=false);


// Execution of IDC code can generate exceptions. Exception objects
// will have the following attributes:
//      file - the source file name
//      line - the line number that was executing when the exception occurred
//      func - the function name
//      pc   - bytecode program counter
// For runtime errors, the following additional attributes exist:
//      qerrno - runtime error code
//      description - text description of the runtime error

/// Execute an IDC function.
/// \param[out] result  pointer to idc_value_t to hold the return value of the function.
///                     If execution fails, this variable will contain
///                     the exception information.
///                     Can be nullptr if return value is not required.
/// \param fname        function name. User-defined functions, built-in functions,
///                     and plugin-defined functions are accepted.
/// \param args         array of parameters
/// \param argsnum      number of parameters to pass to 'fname'.
///                     This number should be equal to number of parameters
///                     the function expects.
/// \param[out] errbuf  buffer for the error message
/// \param resolver     callback object to get values of undefined variables
///                     This object will be called if IDC function contains
///                     references to undefined variables. May be nullptr.
/// \retval true   ok
/// \retval false  error, see errbuf

idaman bool ida_export call_idc_func(
        idc_value_t *result,
        const char *fname,
        const idc_value_t args[],
        size_t argsnum,
        qstring *errbuf=nullptr,
        idc_resolver_t *resolver=nullptr);


/// Compile and execute IDC function(s) from file.
/// \param result       ptr to idc_value_t to hold result of the function.
///                     If execution fails, this variable will contain
///                     the exception information.
///                     You may pass nullptr if you are not interested in the returned
///                     value.
/// \param path         text file containing text of IDC functions
/// \param func         function name to execute
/// \param args         array of parameters
/// \param argsnum      number of parameters to pass to 'fname'
///                     This number should be equal to number of parameters
///                     the function expects.
/// \param[out] errbuf  buffer for the error message
/// \retval true   ok
/// \retval false  error, see errbuf

THREAD_SAFE inline bool exec_idc_script(
        idc_value_t *result,
        const char *path,
        const char *func,
        const idc_value_t args[],
        size_t argsnum,
        qstring *errbuf=nullptr)
{
  if ( !compile_idc_file(path, errbuf) )
    return false;
  return call_idc_func(result, func, args, argsnum, errbuf);
}


/// Compile and execute IDC statements or expressions.
/// \param result       ptr to idc_value_t to hold result of the function.
///                     If execution fails, this variable will contain
///                     the exception information.
///                     You may pass nullptr if you are not interested in the returned
///                     value.
/// \param line         body of IDC the function
/// \param[out] errbuf  buffer for the error message
/// \param resolver     callback object to get values of undefined variables
///                     This object will be called if IDC function contains
///                     references to undefined variables. May be nullptr.
/// \return success
/// \note see also eval_idc_expr()


idaman bool ida_export eval_idc_snippet(
        idc_value_t *result,
        const char *line,
        qstring *errbuf=nullptr,
        idc_resolver_t *resolver=nullptr);


//------------------------------------------------------------------------
/// Setup lowcnd callbacks to read/write registers.
/// These callbacks will be used by the idc engine to read/write registers
/// while calculating low level breakpoint conditions for local debuggers.

idaman void ida_export setup_lowcnd_regfuncs(idc_func_t *getreg, idc_func_t *setreg);

//------------------------------------------------------------------------
/// Extract type & data from the idc_value_t instance that
/// was passed to parse_config_value().
///
/// \param vtype pointer to storage that will hold the type (\ref IDPOPT_T)
/// \param vdata pointer to storage that contains the value (see \ref IDPOPT_T
///              for what type of data is pointed to.)
/// \param v the value holder
/// \return true in case of success, false if 'v' is of unexpected type
inline THREAD_SAFE bool get_idptype_and_data(int *vtype, const void **vdata, const idc_value_t &v)
{
  switch ( v.vtype )
  {
    case VT_STR:   *vtype = IDPOPT_STR, *vdata = v.c_str(); break;
    case VT_LONG:  *vtype = IDPOPT_NUM; *vdata = &v.num; break;
    case VT_WILD:  *vtype = IDPOPT_BIT; *vdata = &v.num; break;
    case VT_INT64: *vtype = IDPOPT_I64; *vdata = &v.i64; break;
    case VT_PVOID: *vtype = IDPOPT_CST; *vdata = v.pvoid; break;
    default: return false;
  }
  return true;
}

/// Create an idc execution exception object.
/// This helper function can be used to return an exception from C++ code to IDC.
/// In other words this function can be called from idc_func_t() callbacks.
/// Sample usage: if ( !ok ) return throw_idc_exception(r, "detailed error msg");
/// \param r object to hold the exception object
/// \param desc exception description
/// \return eExecThrow

idaman error_t ida_export throw_idc_exception(idc_value_t *r, const char *desc);


#endif /* _EXPR_H */
