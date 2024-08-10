/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __IDALIB_HPP
#define __IDALIB_HPP

#include <pro.h>

/*! \file idalib.hpp

  \brief Contains the IDA as library functions.
*/

/// \brief Initialize ida as library
/// \param argc Optional parameters count for advanced usage
/// \param argv Optional parameters list for advanced usage
/// \return 0 if successfully initialized, non zero in case of errors
idaman int ida_export init_library(int argc = 0, char *argv[] = nullptr);


/// \brief Open the database specified in file_path argument
/// If the database did not exist, a new database will be created and
/// the input file will be loaded.
/// \param file_path the file name to be loaded
/// \param run_auto if set to true, library will run also auto analysis
/// \return 0 if successfully opened, otherwise error code
idaman int ida_export open_database(const char *file_path, bool run_auto);


/// \brief Close the current database
/// \param save boolean value, save or discard changes
idaman void ida_export close_database(bool save);


#endif // __IDALIB_HPP
