/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *
 *      Graph drawing support
 *
 */

#ifndef __GDLDRAW_HPP
#define __GDLDRAW_HPP

#include <funcs.hpp>

/*! \file gdl.hpp

  \brief Low level graph drawing operations

*/

//-------------------------------------------------------------------------
// forward declarations:
class node_iterator;
class qflow_chart_t;
class gdl_graph_t;

/// Flow chart block types
enum fc_block_type_t
{
  fcb_normal,    ///< normal block
  fcb_indjump,   ///< block ends with indirect jump
  fcb_ret,       ///< return block
  fcb_cndret,    ///< conditional return block
  fcb_noret,     ///< noreturn block
  fcb_enoret,    ///< external noreturn block (does not belong to the function)
  fcb_extern,    ///< external normal block
  fcb_error,     ///< block passes execution past the function end
};

#ifndef SWIG
#define DECLARE_HELPER(decl)                                        \
decl node_iterator *ida_export node_iterator_goup(node_iterator *); \
decl void ida_export create_qflow_chart(qflow_chart_t &);           \
decl bool ida_export append_to_flowchart(qflow_chart_t &, ea_t, ea_t); \
decl fc_block_type_t ida_export fc_calc_block_type(const qflow_chart_t &, size_t); \
decl bool ida_export create_multirange_qflow_chart(qflow_chart_t &, const rangevec_t &);
#else
#define DECLARE_HELPER(decl)
#endif // SWIG

DECLARE_HELPER(idaman)

//-------------------------------------------------------------------------
/// Set of integer constants
class intset_t : public std::set<int>
{
public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  size_t idaapi print(char *buf, size_t bufsize) const;
  const char *idaapi dstr(void) const;
  bool has(int value) const
  {
    const_iterator p = find(value);
    const_iterator q = end();
    return p != q;
  }
};

typedef qvector<intvec_t> array_of_intvec_t;

/// Map of integer constants to integer constants
class intmap_t : public std::map<int, int>
{
public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  size_t idaapi print(char *buf, size_t bufsize) const;
  const char *idaapi dstr(void) const;
};

typedef qvector<intmap_t> array_of_intmap_t;

//-------------------------------------------------------------------------
/// Edge connecting two graph nodes
struct edge_t
{
  int src = 0;  ///< source node number
  int dst = 0;  ///< destination node number
  edge_t(int x=0, int y=0) : src(x), dst(y) {}
  bool operator < (const edge_t &y) const
    { return src < y.src || (src == y.src && dst < y.dst); }
  bool operator == (const edge_t &y) const
    { return src == y.src && dst == y.dst; }
  bool operator != (const edge_t &y) const
    { return src != y.src || dst != y.dst; }
};
DECLARE_TYPE_AS_MOVABLE(edge_t);

struct edgevec_t : public qvector<edge_t>
{
};

struct edgeset_t;
struct edge_segs_vec_t;
struct edge_infos_t;
struct destset_t;

enum edge_type_t
{
  EDGE_NONE     = 0,
  EDGE_TREE     = 1,
  EDGE_FORWARD  = 2,
  EDGE_BACK     = 3,
  EDGE_CROSS    = 4,
  EDGE_SUBGRAPH = 5              // edge of a subgraph (used in collapse)
};

//-------------------------------------------------------------------------
/// Set of graph nodes
class node_set_t : public intset_t
{
public:
  idaapi node_set_t(void) {}
  idaapi node_set_t(int node) { insert(node); }
  idaapi node_set_t(const gdl_graph_t *g);
  bool idaapi add(int node) { return insert(node).second; }
  void idaapi sub(int node) { erase(node); }
  void idaapi sub(const node_set_t &r);
  void idaapi add(const node_set_t &r);
  void idaapi intersect(const node_set_t &r);
  void idaapi extract(intvec_t &out) const;
  int  idaapi first(void) const { return empty() ? -1 : *begin(); }
};

typedef qvector<node_set_t> array_of_node_set_t;

//-------------------------------------------------------------------------
/// Node ordering in a graph.
/// Maps a node number to a number describing its
/// order in the graph (and vice versa).
class node_ordering_t
{
  intvec_t node_by_order;           ///< ordered sequence of node numbers
  intvec_t order_by_node;           ///< node number => index in #node_by_order

  void ensure_order_by_node()
  {
    if ( order_by_node.empty() )
    {
      size_t n = size();
      order_by_node.resize(n, -1);
      for ( size_t i = 0; i < n; i++ )
      {
        int idx = node_by_order[i];
        if ( idx != -1 )
          order_by_node[idx] = i;
      }
    }
  }

public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void idaapi clear(void)
  {
    node_by_order.clear();
    order_by_node.clear();
  }

  void idaapi resize(int n)
  {
    clear();
    if ( n >= 0 )
      node_by_order.resize(n, -1);
  }

  size_t idaapi size(void) const
  {
    return node_by_order.size();
  }

  void idaapi set(int _node, int num)
  {
    ensure_order_by_node();
    if ( num >= 0 && num < node_by_order.size()
      && _node >= 0 && _node < order_by_node.size() )
    {
      node_by_order[num] = _node;
      order_by_node[_node] = num;
    }
  }

  bool idaapi clr(int _node)
  {
    if ( _node < 0 )
      return false;
    ensure_order_by_node();
    if ( _node >= order_by_node.size() )
      return false;
    int old = order_by_node[_node];
    if ( old < 0 || old >= node_by_order.size() )
      return false;
    order_by_node[_node] = -1;
    node_by_order[old] = -1;
    // shift all order numbers higher than the deleted order number by one
    size_t n = size();
    for ( size_t i = 0; i < n; i++ )
      if ( order_by_node[i] > old )
        order_by_node[i]--;
    int rest = n - old - 1;
    if ( rest > 0 )
      memmove(&node_by_order[old], &node_by_order[old+1], rest*sizeof(int));
    return true;
  }

  int idaapi node(size_t _order) const
  {
    return _order < node_by_order.size() ? node_by_order[_order] : -1;
  }

  int idaapi order(int _node)
  {
    ensure_order_by_node();
    return (_node >= 0 && _node < order_by_node.size()) ? order_by_node[_node] : -1;
  }
};

//-------------------------------------------------------------------------
/// Node iterator (used to draw graphs)
class node_iterator
{
  DECLARE_HELPER(friend)
  friend class gdl_graph_t;
  const gdl_graph_t *g;
  int i;
  node_iterator &_goup(void);
  node_iterator &goup(void) { return *node_iterator_goup(this); }
public:
  node_iterator(const gdl_graph_t *_g, int n) : g(_g), i(n) {}
  node_iterator &operator++(void) { i++; return goup(); }
  bool operator==(const node_iterator &n) const { return i == n.i && g == n.g; }
  bool operator!=(const node_iterator &n) const { return !(*this == n); }
  int operator*(void) const { return i; }
};

//-------------------------------------------------------------------------
/// gdl graph interface - includes only functions required to draw it
class gdl_graph_t
{
  // does a path from 'm' to 'n' exist?
  bool idaapi path(node_set_t &visited, int m, int n) const;
public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  virtual ~gdl_graph_t() {}
  virtual char *idaapi get_node_label(char *iobuf, int iobufsize, int n) const { qnotused(iobufsize); qnotused(n); iobuf[0] = '\0'; return iobuf; }
  virtual void idaapi print_graph_attributes(FILE *fp) const { qnotused(fp); }
  virtual bool idaapi print_node(FILE *fp, int n) const { qnotused(fp); qnotused(n); return false; }
  virtual bool idaapi print_edge(FILE *fp, int i, int j) const { qnotused(fp); qnotused(i); qnotused(j); return false; }
  virtual void idaapi print_node_attributes(FILE *fp, int n) const { qnotused(fp); qnotused(n); }
  virtual int  idaapi size(void) const = 0;                    // number of the max node number
  virtual int  idaapi node_qty(void) const { return size(); }  // number of alive nodes
  virtual bool idaapi exists(int node) const { qnotused(node); return true; }
  virtual int  idaapi entry(void) const { return 0; }
  virtual int  idaapi exit(void) const { return size()-1; }
  virtual int  idaapi nsucc(int node) const = 0;
  virtual int  idaapi npred(int node) const = 0;
  virtual int  idaapi succ(int node, int i) const = 0;
  virtual int  idaapi pred(int node, int i) const = 0;
  virtual bool idaapi empty(void) const { return node_qty() == 0; }
  virtual bgcolor_t idaapi get_node_color(int n) const { qnotused(n); return DEFCOLOR; }
  virtual bgcolor_t idaapi get_edge_color(int i, int j) const { qnotused(i); qnotused(j); return DEFCOLOR; }
          void idaapi gen_gdl(FILE *fp) const;
          void idaapi gen_gdl(const char *file) const;
          size_t idaapi nedge(int node, bool ispred) const { return ispred ? npred(node) : nsucc(node); }
          int  idaapi edge(int node, int i, bool ispred) const { return ispred ? pred(node, i) : succ(node, i); }
          int  idaapi front(void) { return *begin(); }
  node_iterator idaapi begin(void) const { return node_iterator(this, 0).goup(); }
  node_iterator idaapi end(void)   const { return node_iterator(this, size()); }
  // does a path from 'm' to 'n' exist?
  bool idaapi path_exists(int m, int n) const { node_set_t v; return path(v, m, n); }

  void idaapi gen_dot(FILE *fp) const;
  void idaapi gen_dot(const char *file) const;
};


/// Create GDL file for graph

idaman void ida_export gen_gdl(const gdl_graph_t *g, const char *fname);


/// Display GDL file by calling wingraph32.
/// The exact name of the grapher is taken from the configuration file
/// and set up by setup_graph_subsystem().
/// The path should point to a temporary file: when wingraph32
/// succeeds showing the graph, the input file will be deleted.
/// \return error code from os, 0 if ok

idaman int ida_export display_gdl(const char *fname);


//-------------------------------------------------------------------------
// Build and display program graphs

/// Build and display a flow graph.
/// \param filename  output file name. the file extension is not used. maybe nullptr.
/// \param title     graph title
/// \param pfn       function to graph
/// \param ea1, ea2  if pfn == nullptr, then the address range
/// \param gflags    combination of \ref CHART_1.
///                  if none of #CHART_GEN_DOT, #CHART_GEN_GDL, #CHART_WINGRAPH
///                  is specified, the function will return false
/// \return success. if fails, a warning message is displayed on the screen

idaman bool ida_export gen_flow_graph(
        const char *filename,
        const char *title,
        func_t *pfn,
        ea_t ea1,
        ea_t ea2,
        int gflags);

/// \defgroup CHART_1 Flow graph building flags
/// Passed as flags parameter to:
///   - gen_flow_graph()
///   - gen_simple_call_chart()
///   - gen_complex_call_chart()
///@{
#define CHART_PRINT_NAMES 0x1000 ///< print labels for each block?
#define CHART_GEN_DOT     0x2000 ///< generate .dot file (file extension is forced to .dot)
#define CHART_GEN_GDL     0x4000 ///< generate .gdl file (file extension is forced to .gdl)
#define CHART_WINGRAPH    0x8000 ///< call grapher to display the graph
///@}


/// Build and display a simple function call graph.
/// \param filename  output file name. the file extension is not used. maybe nullptr.
/// \param wait      message to display during graph building
/// \param title     graph title
/// \param gflags    combination of #CHART_NOLIBFUNCS and \ref CHART_1.
///                  if none of #CHART_GEN_DOT, #CHART_GEN_GDL, #CHART_WINGRAPH
///                  is specified, the function will return false.
/// \return success. if fails, a warning message is displayed on the screen

idaman bool ida_export gen_simple_call_chart(
        const char *filename,
        const char *wait,
        const char *title,
        int gflags);


/// Build and display a complex xref graph.
/// \param filename         output file name. the file extension is not used. maybe nullptr.
/// \param wait             message to display during graph building
/// \param title            graph title
/// \param ea1, ea2         address range
/// \param flags            combination of \ref CHART_2 and \ref CHART_1.
///                         if none of #CHART_GEN_DOT, #CHART_GEN_GDL, #CHART_WINGRAPH
///                         is specified, the function will return false.
/// \param recursion_depth  optional limit of recursion
/// \return success. if fails, a warning message is displayed on the screen

idaman bool ida_export gen_complex_call_chart(
        const char *filename,
        const char *wait,
        const char *title,
        ea_t ea1,
        ea_t ea2,
        int flags,
        int32 recursion_depth=-1);

/// \defgroup CHART_2 Call chart building flags
/// Passed as flags parameter to gen_complex_call_chart()
///@{
#define CHART_NOLIBFUNCS       0x0400 ///< don't include library functions in the graph
#define CHART_REFERENCING      0x0001 ///< references to the addresses in the list
#define CHART_REFERENCED       0x0002 ///< references from the addresses in the list
#define CHART_RECURSIVE        0x0004 ///< analyze added blocks
#define CHART_FOLLOW_DIRECTION 0x0008 ///< analyze references to added blocks only in the direction of the reference who discovered the current block
#define CHART_IGNORE_XTRN      0x0010
#define CHART_IGNORE_DATA_BSS  0x0020
#define CHART_IGNORE_LIB_TO    0x0040 ///< ignore references to library functions
#define CHART_IGNORE_LIB_FROM  0x0080 ///< ignore references from library functions
#define CHART_PRINT_COMMENTS   0x0100
#define CHART_PRINT_DOTS       0x0200 ///< print dots if xrefs exist outside of the range recursion depth
///@}


/// Setup the user-defined graph colors and graph viewer program.
/// This function is called by the GUI at the beginning, so no need to call
/// it again.

idaman void ida_export setup_graph_subsystem(const char *_grapher, bgcolor_t (idaapi *get_graph_color)(int color));


class cancellable_graph_t : public gdl_graph_t
{
public:
  mutable bool cancelled = false;
  char padding[3]; // make the class nicely aligned. otherwise we have
                   // problems with gcc in qflow_chart_t.
  virtual ~cancellable_graph_t() {}
  bool idaapi check_cancel(void) const;
};

//--------------------------------------------------------------------------
/// Information about a basic block of a \ref qflow_chart_t
struct qbasic_block_t : public range_t
{
  intvec_t succ; ///< list of node successors
  intvec_t pred; ///< list of node predecessors
};

/// Does this block never return?
inline THREAD_SAFE bool is_noret_block(fc_block_type_t btype)
{
  return btype == fcb_noret || btype == fcb_enoret;
}

/// Does this block return?
inline THREAD_SAFE bool is_ret_block(fc_block_type_t btype)
{
  return btype == fcb_ret || btype == fcb_cndret;
}

/// \defgroup FC_ Flow chart flags
/// Passed as 'flags' parameter to qflow_chart_t
///@{
#define FC_PRINT     0x0001 ///< print names (used only by display_flow_chart())
#define FC_NOEXT     0x0002 ///< do not compute external blocks. Use this to prevent jumps leaving the
                            ///< function from appearing in the flow chart. Unless specified, the
                            ///< targets of those outgoing jumps will be present in the flow
                            ///< chart under the form of one-instruction blocks
#define FC_RESERVED  0x0004 // former FC_PREDS
#define FC_APPND     0x0008 ///< multirange flowchart (set by append_to_flowchart)
#define FC_CHKBREAK  0x0010 ///< build_qflow_chart() may be aborted by user
#define FC_CALL_ENDS 0x0020 ///< call instructions terminate basic blocks
#define FC_NOPREDS   0x0040 ///< do not compute predecessor lists
#define FC_OUTLINES  0x0080 ///< include outlined code (with FUNC_OUTLINE)
///@}

/// A flow chart for a function, or a set of address ranges
class qflow_chart_t : public cancellable_graph_t
{
public:
  typedef qvector<qbasic_block_t> blocks_t;
  DECLARE_HELPER(friend)
  qstring title;
  range_t bounds;        ///< overall bounds of the qflow_chart_t instance
  func_t *pfn = nullptr; ///< the function this instance was built upon
  int flags = 0;         ///< flags. See \ref FC_
  blocks_t blocks;       ///< basic blocks
  int nproper = 0;       ///< number of basic blocks belonging to the specified range

  idaapi qflow_chart_t(void) {}
  idaapi qflow_chart_t(const char *_title, func_t *_pfn, ea_t _ea1, ea_t _ea2, int _flags)
    : title(_title), bounds(_ea1, _ea2), pfn(_pfn), flags(_flags)
  {
    refresh();
  }
  virtual ~qflow_chart_t() {}
  void idaapi create(const char *_title, func_t *_pfn, ea_t _ea1, ea_t _ea2, int _flags)
  {
    title  = _title;
    pfn    = _pfn;
    bounds = range_t(_ea1, _ea2);
    flags  = _flags;
    refresh();
  }
  void idaapi create(const char *_title, const rangevec_t &ranges, int _flags)
  {
    title  = _title;
    flags  = _flags;
    create_multirange_qflow_chart(*this, ranges);
  }
  void idaapi append_to_flowchart(ea_t ea1, ea_t ea2) { ::append_to_flowchart(*this, ea1, ea2); }
  void idaapi refresh(void) { create_qflow_chart(*this); }
  fc_block_type_t calc_block_type(size_t blknum) const
    { return fc_calc_block_type(*this, blknum); }
  bool is_ret_block(size_t blknum) const { return ::is_ret_block(calc_block_type(blknum)); }
  bool is_noret_block(size_t blknum) const { return ::is_noret_block(calc_block_type(blknum)); }
  virtual void idaapi print_node_attributes(FILE *fp, int n) const override { qnotused(fp); qnotused(n);  }
  virtual int  idaapi nsucc(int node) const override { return int(blocks[node].succ.size()); }
  virtual int  idaapi npred(int node) const override { return int(blocks[node].pred.size()); }
  virtual int  idaapi succ(int node, int i) const override { return blocks[node].succ[i]; }
  virtual int  idaapi pred(int node, int i) const override { return blocks[node].pred[i]; }
  virtual char *idaapi get_node_label(char *iobuf, int iobufsize, int n) const override { qnotused(iobuf); qnotused(iobufsize); qnotused(n); return nullptr; }
  virtual int  idaapi size(void) const override { return int(blocks.size()); }
  bool idaapi print_names(void) const { return (flags & FC_PRINT) != 0; }
};

#endif // __GDLDRAW_HPP
