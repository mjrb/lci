/**
 * Structures and functions for grouping lexemes into tokens.  The tokenizer
 * reads through an array of lexemes (generated by the lexer) and groups them
 * into tokens based on their structure.  In addition, some lexemes with
 * semantic meaning (such as integers, floats, strings, and booleans) will have
 * their values extracted and stored.
 *
 * \file   tokenizer.h
 *
 * \author Justin J. Meza
 *
 * \date   2010-2012
 */

#ifndef __TOKENIZER_H__
#define __TOKENIZER_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "lexer.h"
#include "error.h"

#undef DEBUG

/**
 * Represents a token type.  All of the token type names correspond to either
 * the semantic type of token data or the lexemes which make up the particular
 * token.
 *
 * \note Remember to update the keywords array (below) with the token image.
 */
typedef enum {
	TT_INTEGER,     /**< Integer literal. */
	TT_FLOAT,       /**< Decimal literal. */
	TT_STRING,      /**< String literal. */
	TT_IDENTIFIER,  /**< Identifier literal. */
	TT_BOOLEAN,     /**< Boolean literal. */
	TT_IT,          /**< \ref impvar "Implicit variable". */
	TT_ITZLIEKA,    /**< Inherited object declaration. */
	TT_NOOB,        /**< Nil keyword. */
	TT_NUMBR,       /**< Integer keyword. */
	TT_NUMBAR,      /**< Decimal keyword. */
	TT_TROOF,       /**< Boolean keyword. */
	TT_YARN,        /**< String keyword. */
	TT_BUKKIT,      /**< Array. */
	TT_EOF,         /**< End of file. */
	TT_NEWLINE,     /**< Newline. */
	TT_HAI,         /**< Beginning of main block. */
	TT_KTHXBYE,     /**< End of main block. */
	TT_HASA,        /**< Variable declaration. */
	TT_HASAN,       /**< Variable declaration. */
	TT_ITZA,        /**< Variable type initialization. */
	TT_ITZ,         /**< Variable value initialization. */
	TT_RNOOB,       /**< Deallocation. */
	TT_R,           /**< Assignment. */
	TT_ANYR,        /**< User-defined function argument separator. */
	TT_AN,          /**< Built-in function argument separator. */
	TT_SUMOF,       /**< Addition. */
	TT_DIFFOF,      /**< Subtraction. */
	TT_PRODUKTOF,   /**< Multiplication. */
	TT_QUOSHUNTOF,  /**< Division. */
	TT_MODOF,       /**< Modulo. */
	TT_BIGGROF,     /**< Greater than. */
	TT_SMALLROF,    /**< Less than. */
	TT_BOTHOF,      /**< Logical AND. */
	TT_EITHEROF,    /**< Logical OR. */
	TT_WONOF,       /**< Logical XOR. */
	TT_NOT,         /**< Logical NOT. */
	TT_MKAY,        /**< Infinite arity argument delimiter. */
	TT_ALLOF,       /**< Infinite arity logical AND. */
	TT_ANYOF,       /**< Infinite arity logical OR. */
	TT_BOTHSAEM,    /**< Equality. */
	TT_DIFFRINT,    /**< Inequality. */
	TT_MAEK,        /**< Cast. */
	TT_A,           /**< Cast target separator. */
	TT_ISNOWA,      /**< In-place cast. */
	TT_VISIBLE,     /**< Print. */
	TT_INVISIBLE,   /**< Print to standard error. */
	TT_SMOOSH,      /**< String concatenation. */
	TT_BANG,        /**< Exclamation point (!) */
	TT_GIMMEH,      /**< Input. */
	TT_ORLY,        /**< Conditional. */
	TT_YARLY,       /**< True branch. */
	TT_MEBBE,       /**< Else branch. */
	TT_NOWAI,       /**< False branch. */
	TT_OIC,         /**< Conditional and switch delimiter. */
	TT_WTF,         /**< Switch. */
	TT_OMG,         /**< Case. */
	TT_OMGWTF,      /**< Default case. */
	TT_GTFO,        /**< Break or return without value. */
	TT_IMINYR,      /**< Loop beginning. */
	TT_UPPIN,       /**< Auto increment loop variable. */
	TT_NERFIN,      /**< Auto decrement loop variable. */
	TT_YR,          /**< Function name delimiter. */ 
	TT_TIL,         /**< Do until. */
	TT_WILE,        /**< Do while. */
	TT_IMOUTTAYR,   /**< Loop ending. */
	TT_HOWIZ,       /**< Function definition beginning. */
	TT_IZ,          /**< Function scope delimiter. */
	TT_IFUSAYSO,    /**< Function definition end. */
	TT_FOUNDYR,     /**< Return with value. */
	TT_SRS,         /**< Indirect variable access. */
	TT_APOSTROPHEZ, /**< Array slot access ('Z). */
	TT_OHAIIM,      /**< Alternate array declaration. */
	TT_IMLIEK,      /**< Alternate inherited object declaration. */
	TT_KTHX,        /**< End of alternate array declaration. */
	TT_IDUZ,        /**< System command. */
	TT_CANHAS,      /**< Library import declaration. */
	TT_QUESTION,    /**< End of library import declaration. */
	TT_NOM,         /**< Array auto insert */

	TT_ENDOFTOKENS  /**< Sentinel end of this enum -- don't move it! */
} TokenType;

static const char *keywords[] = {
	"",            /* TT_INTEGER */
	"",            /* TT_FLOAT */
	"",            /* TT_STRING */
	"",            /* TT_IDENTIFIER */
	"",            /* TT_BOOLEAN */
	"IT",          /* TT_IT */
	"ITZ LIEK A",  /* TT_ITZLIEKA */
	"NOOB",        /* TT_NOOB */
	"NUMBR",       /* TT_NUMBR */
	"NUMBAR",      /* TT_NUMBAR */
	"TROOF",       /* TT_TROOF */
	"YARN",        /* TT_YARN */
	"BUKKIT",      /* TT_BUKKIT */
	"",            /* TT_EOF */
	"",            /* TT_NEWLINE */
	"HAI",         /* TT_HAI */
	"KTHXBYE",     /* TT_KTHXBYE */
	"HAS A",       /* TT_HASA */
	"HAS AN",      /* TT_HASAN */
	"ITZ A",       /* TT_ITZA */
	"ITZ",         /* TT_ITZ */
	"R NOOB",      /* TT_RNOOB */
	"R",           /* TT_R */
	"AN YR",       /* TT_ANYR */
	"AN",          /* TT_AN */
	"SUM OF",      /* TT_SUMOF */
	"DIFF OF",     /* TT_DIFFOF */
	"PRODUKT OF",  /* TT_PRODUKTOF */
	"QUOSHUNT OF", /* TT_QUOSHUNTOF */
	"MOD OF",      /* TT_MODOF */
	"BIGGR OF",    /* TT_BIGGROF */
	"SMALLR OF",   /* TT_SMALLROF */
	"BOTH OF",     /* TT_BOTHOF */
	"EITHER OF",   /* TT_EITHEROF */
	"WON OF",      /* TT_WONOF */
	"NOT",         /* TT_NOT */
	"MKAY",        /* TT_MKAY */
	"ALL OF",      /* TT_ALLOF */
	"ANY OF",      /* TT_ANYOF */
	"BOTH SAEM",   /* TT_BOTHSAEM */
	"DIFFRINT",    /* TT_DIFFRINT */
	"MAEK",        /* TT_MAEK */
	"A",           /* TT_A */
	"IS NOW A",    /* TT_ISNOWA */
	"VISIBLE",     /* TT_VISIBLE */
	"INVISIBLE",   /* TT_INVISIBLE */
	"SMOOSH",      /* TT_SMOOSH */
	"!",           /* TT_BANG */
	"GIMMEH",      /* TT_GIMMEH */
	"O RLY",       /* TT_ORLY */
	"YA RLY",      /* TT_YARLY */
	"MEBBE",       /* TT_MEBBE */
	"NO WAI",      /* TT_NOWAI */
	"OIC",         /* TT_OIC */
	"WTF",         /* TT_WTF */
	"OMG",         /* TT_OMG */
	"OMGWTF",      /* TT_OMGWTF */
	"GTFO",        /* TT_GTFO */
	"IM IN YR",    /* TT_IMINYR */
	"UPPIN",       /* TT_UPPIN */
	"NERFIN",      /* TT_NERFIN */
	"YR",          /* TT_YR */
	"TIL",         /* TT_TIL */
	"WILE",        /* TT_WILE */
	"IM OUTTA YR", /* TT_IMOUTTAYR */
	"HOW IZ",      /* TT_HOWIZ */
	"IZ",          /* TT_IZ */
	"IF U SAY SO", /* TT_IFUSAYSO */
	"FOUND YR",    /* TT_FOUNDYR */
	"SRS",         /* TT_SRS */
	"'Z",          /* TT_APOSTROPHEZ */
	"O HAI IM",    /* TT_OHAIIM */
	"IM LIEK",     /* TT_IMLIEK */
	"KTHX",        /* TT_KTHX */
	"I DUZ",       /* TT_IDUZ */
	"CAN HAS",     /* TT_CANHAS */
	"?",           /* TT_QUESTION */
	"NOM",         /* TT_NOM */
	""             /* TT_ENDOFTOKENS */
};

/**
 * Stores token data with semantic meaning.
 */
typedef union {
	long long i;   /**< Integer data. */
	float f; /**< Decimal data. */
} TokenData;

/**
 * Stores a token type and any parsed values.
 */
typedef struct {
	TokenType type;    /**< The type of token. */
	TokenData data;    /**< The stored data of type \a type. */
	char *image;       /**< The characters that comprise the token. */
	const char *fname; /**< The name of the file containing the token. */
	unsigned int line; /**< The line number the token was on. */
} Token;

/**
 * \name Utilities
 *
 * Functions for performing helper tasks.
 */
/**@{*/
int isInteger(const char *);
int isFloat(const char *);
int isString(const char *);
int isIdentifier(const char *);
Token *isKeyword(LexemeList *, unsigned int *);
/**@}*/

/**
 * \name Token modifiers
 *
 * Functions for creating and deleting tokens.
 */
/**@{*/
Token *createToken(TokenType, const char *, const char *, unsigned int);
void deleteToken(Token *);
int addToken(Token ***, unsigned int *, Token*);
void deleteTokens(Token **);
unsigned int acceptLexemes(LexemeList *, unsigned int, const char *);
/**@}*/

/**
 * \name Lexeme tokenizer
 *
 * Generates tokens from lexemes.
 */
/**@{*/
Token **tokenizeLexemes(LexemeList *);
/**@}*/

#endif /* __TOKENIZER_H__ */
