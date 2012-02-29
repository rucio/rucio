% atlasart.cls
% Template class for ATLAS notes
% 2009-03-27 Marco Delmastro <Marco.Delmastro@cern.ch>

% --- Class structure: identification part
% ---
\ProvidesClass{atlasnote}[2009/07/30 version 3.0 ATLAS Notes]
\NeedsTeXFormat{LaTeX2e}

% --- Class structure: initial code part
% ---

% Defaults for title page
\newdimen\AN@skipbeforetitle
\AN@skipbeforetitle=60\p@
\newcommand\skipbeforetitle[1]{
  \AN@skipbeforetitle=#1
}

\def\@title{Title goes here}
\def\@author{The ATLAS collaboration}
\def\@date{\today}

%
% Author(s)
%

%\def\@makefnmark{\hbox{$^{\@thefnmark)}$}}
%\def\author#1{%% Treat the list of authors
%\setcounter{footnote}{0}\def\@currentlabel{}%
%\begingroup\def\thefootnote{\arabic{footnote}}
%\global\@topnum\z@ \large\begin{center}{\lineskip.5em
%\begin{tabular}[t]{c}#1\end{tabular}\par}
%\end{center}\par\vskip1.5em\@thanks\endgroup}
%\newenvironment{Authlist}{\begin{center}}{\end{center}}

% Draft version 
\def\@draftversion{}
\newcommand{\draftversion}[1]%
{
  \def\@draftversion{#1}
}

% Draft heading code
\newcommand{\draftheading}%
{
  % 
  % compute the time in hours and minutes
  % make new variables \timehh and \timemm
  % 
  \newcount\timehh\newcount\timemm
  \timehh=\time 
  \divide\timehh by 60 \timemm=\time
  \count255=\timehh\multiply\count255 by -60 \advance\timemm by \count255
  % put in header
  \markboth%
  % --- Left mark
  {\hspace*{\fill}{\protect\small\bf \fbox{DRAFT}}
    \hspace*{\fill}
    \protect\makebox[0pt][r]{\protect\small\sl\today\ -- 
      \ifnum\timehh<10 0\fi\number\timehh\,:\,\ifnum\timemm<10 0\fi\number\timemm}
  }%--- right mark
  {\protect\makebox[0pt][l]{\protect\small\sl\today\ -- 
      \ifnum\timehh<10 0\fi\number\timehh\,:\,\ifnum\timemm<10 0\fi\number\timemm}
    \hspace*{\fill}
    {\protect\small\bf \fbox{DRAFT}}
    \hspace*{\fill}}
  %
  \pagestyle{myheadings}
}

% ATLAS note number
%\def\@atlasnote{}
%\newcommand{\atlasnote}[1]{\def\@atlasnote{#1}}

% Submission details
\def\@subprepend{To be submitted to }
\newcommand{\subprepend}[1]{\def\@subprepend{#1}}
\def\@journal{}
\newcommand{\journal}[1]{\def\@journal{#1}}

% Abstract text
\def\@abstracttext{}
\newcommand{\abstracttext}[1]{\def\@abstracttext{#1}}

% Shortcut to add submission text
\newcommand{\submitted}%
{
  \ifx\@journal\@empty\mbox{}%
  \else
  \vskip 0.8in plus 2in%
  \begin{center}%
    \@subprepend\space {\it \@journal}%
    \vskip 1.5em%
  \end{center}%
  \vskip 0.5in
  \fi
}

% --- Class structure: declaration of options part
% ---
\let\if@CoverPage\iffalse
\DeclareOption{coverpage}{\let\if@CoverPage\iftrue}
\let\if@usetikz\iffalse
\DeclareOption{usetikz}{\let\if@usetikz\iftrue}

% This class extends the article class
% Read all the atlasnote options, pass them to article
%\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
% --- Class structure: execution of options part
% ---
\ProcessOptions \relax

% --- Class structure: declaration of options part
% ---
\LoadClass[titlepage,a4paper,11pt]{article}

% --- Class structure: main code part
% ---

% ATLAS Cover Page
\if@CoverPage \RequirePackage[clearpage,atlasnote]{atlascover}[2009/11/17] \fi

% Redefine the page size
\RequirePackage{geometry}
\geometry{
  a4paper,%
  textwidth=16cm,% 
  textheight=23.2cm,%
  marginparsep=7pt,% 
  marginparwidth=2.5cm%
}

% Remove the numbers from all the headings (\section, \subsection, etc.)
%\setcounter{secnumdepth}{-1}


%
% Title page design
%
\RequirePackage{graphicx}

%\RequirePackage{mathptmx}
\RequirePackage{amsmath}
\RequirePackage[varg]{txfonts}

\RequirePackage{lineno}   % This is provided with the package

\newcommand{\maketitlepage}{%
  \null
  \thispagestyle{empty}
  \pagestyle{plain}
  \pagenumbering{arabic}
  \ifx\@draftversion\@empty\mbox{}%
  \else \flushright Draft version \@draftversion \\ 
  \fi
  \begin{center}
    \vspace*{-6mm}
    \includegraphics[width=3cm]{AN_atlaslogo} 
    \hfill 
    \begin{minipage}[b]{7cm}
      \vfill
      \begin{center}
        {\huge \bf \textsf{ATLAS NOTE}}%
        % ATLAS note number, if any 
        % (not used anymore, automatically stamped on PDF by CDS 
        % -- M.D. 30/7/2009)
        %\ifx\@atlasnote\@empty \vskip 2mm \mbox{}%
        %\else \vskip 4mm {\Large \@atlasnote} \vskip 2mm%
        %\fi
        % Date, if any
        \ifx\@date\@empty\mbox{}%       
        \else \vskip 2mm \@date%
        \fi
      \end{center}
      \vfill
    \end{minipage}
    \hfill
    \includegraphics[width=3cm]{AN_cernlogo}    
  \end{center}
  % Add line numebrs to front page content 
  {%
  \ifx\@draftversion\@empty%
  \else\linenumbers
  \fi
  % Title, author(s)
  %\vskip 60\p@
  \vskip \AN@skipbeforetitle
  \begin{center}%
    {\Large\bf \@title \par}%
    \vskip 3em%
    {\large
     \lineskip .75em%
      \begin{tabular}[t]{c}%
        \@author
      \end{tabular}\par}%
  \end{center}\par
  \vfill
  % Abstract
  \if\@abstracttext\@empty\mbox{}%
  \else%
  \begin{center}
    {\bfseries \abstractname}
    \quotation
    \@abstracttext
    \endquotation
  \end{center}
  \fi
  \vfill
  % Submission details
  \submitted
  % Thanks
  \@thanks
  }%
  %\vfil\null%
}

% This some before-and-after code that surrounds the title page. It
% shouldn't need to be modified. I've pulled out the part the actually
% typesets the title page and placed it in the \maketitlepage command
% above.
\renewcommand\maketitle{%
  \begin{titlepage}%
    \let\footnotesize\small%
    \let\footnoterule\relax%
    \let \footnote \thanks%
    \maketitlepage%
  \end{titlepage}%
  \setcounter{footnote}{0}%
  \setcounter{page}{1}%
  \global\let\thanks\relax
  \global\let\maketitle\relax
  \global\let\@thanks\@empty
  \global\let\@author\@empty
  \global\let\@date\@empty
  \global\let\@title\@empty
  \global\let\title\relax
  \global\let\author\relax
  \global\let\date\relax
  \global\let\and\relax
}

% Use \icaption instead of \caption in tables and figures to get a
% caption that is indented. Note that the label should be included
% inside \icaption for it to work properly.
\newlength{\capindent}
\setlength{\capindent}{0.5cm}
\newlength{\capwidth}
\setlength{\capwidth}{\textwidth}
\addtolength{\capwidth}{-2\capindent}
\newlength{\figwidth}
\setlength{\figwidth}{\textwidth}
\addtolength{\figwidth}{-2.0cm}
\newcommand{\icaption}[2][!*!,!]{\hspace*{\capindent}%
  \begin{minipage}{\capwidth}
    \ifthenelse{\equal{#1}{!*!,!}}%
      {\caption{#2}}%
      {\caption[#1]{#2}}
      \vspace*{3mm}
  \end{minipage}}

\AtBeginDocument{
  % If selected, generate ATLAS Cover Page
  \if@CoverPage 
  \AC@PrintAtlasCover
  \fi
  % Automatically generate title page
  \maketitle
  % Add draft heading and line numbers
  \ifx\@draftversion\@empty%
  \else \linenumbers \draftheading 
  \fi
  % Hack for tikz (must be loaded here in order to avoid conflicts with graphicx user in \maketitle}
  \if@usetikz \RequirePackage{tikz} \fi
  %\pagenumbering{arabic} % reset page numbering after title page
}

% That's all, folks!
\endinput
