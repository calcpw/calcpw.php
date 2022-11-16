#!/usr/bin/env php
<?php

  # calcpw.php v0.2b1
  #
  # Copyright (c) 2022, Yahe
  # All rights reserved.
  #
  #
  # usage:
  # ======
  #
  # ./calcpw.php [(--dieharder|--modulobias) <password> <information> [<characterset>]]
  #
  #
  # description:
  # ============
  #
  # This script implements the calc.pw password calculation algorithm and serves as a reference implementation.
  # The calc.pw password calculation contains a key derivation and key expansion function that is combined with
  # an encoding function to produce pseudorandom but reproducible passwords from a secret password and a
  # service-dependent information.
  #
  # The password calculation can be modified by setting additional configuration values:
  #
  # * calc.pw queries a modifiable password length, the password must not be longer than 1024 characters, the
  #   limit has been introduced as the password calculation is meant to be implemented on a microcontroller later
  #   on which will have memory constraints
  #
  # * calc.pw queries a modifiable character set, the character set defines which characters may occur in the
  #   calculated password, the character set consists of one ore more character groups which are split by spaces,
  #   character groups are relevant for the enforcement mode, to simplify the definition of the character set it
  #   is possible to define ranges from a first character to a last character by using a minus sign (e.g. `0-9`
  #   or `A-Z` or `a-z`)
  #
  # * calc.pw queries a modifiable enforcement mode, the enforcement mode makes sure that at least one character
  #   from each character group is contained within the calculated password, the password calculation will continue
  #   until a valid password has been calculated
  #
  #
  # execution:
  # ==========
  #
  # To execute the script you have to call it in the following way:
  #
  # ./calcpw.php [(--dieharder|--modulobias) <password> <information> [<characterset>]]
  #
  # --dieharder    (OPTIONAL) to test the strength of the random number generator the script supports a way to output
  #                           raw pseudorandom data to STDOUT which can then be used by dieharder, when the dieharder
  #                           mode is used, the parameters <password> and <information> must be provided as well
  #
  # --modulobias   (OPTIONAL) the test the resistance of the password encoding against modulo bias the script supports
  #                           a way to output encoded psuedorandom data to STDOUT which can then be used by a modulo
  #                           bias test, when the modulo bias mode is used, the parameters <password> and <information>
  #                           must be provided as well while the parameter <characterset> may be provided as well
  #
  # <password>     (OPTIONAL) when the dieharder or modulo bias mode is used then the password must be provided
  #
  # <information>  (OPTIONAL) when the dieharder or modulo bias mode is used then the information must be provided
  #
  # <characterset> (OPTIONAL) when the modulo bias mode is used then the character set parameter may be provided
  #
  # When no parameter is provided then the interactive mode of the script is triggered.

  # set default parameters for generated passwords
  define("DEFAULT_CHARSET", "0-9 A-Z a-z");
  define("DEFAULT_ENFORCE", false);
  define("DEFAULT_LENGTH",  16);

  # this will be dependent on the speed of the Raspberry Pi Pico
  define("PBKDF2_ITERATIONS", 512000);

  # ===== DO NOT EDIT HERE =====

  # define argument to execute test modes
  define("ARG_DIEHARDER",  "--dieharder");
  define("ARG_MODULOBIAS", "--modulobias");

  # define execution mode values
  define("MODE_DEFAULT",    0);
  define("MODE_DIEHARDER",  1);
  define("MODE_MODULOBIAS", 2);

  function println($text) {
    print($text.PHP_EOL);
  }

  # based on https://stackoverflow.com/a/51747444 but heavily rewritten
  function readtext($text = "", $default = "", $replace_char = null) {
    $result = null;

    if (readline_callback_handler_install("", function(){}) && (stream_set_blocking(STDIN, false))) {
      try {
        $char1   = null;
        $char2   = null;
        $char3   = null;
        $char4   = null;
        $temp    = "";
        $string  = $default;

        print($text.": ".$string);

        do {
          $temp = stream_get_contents(STDIN);
          if (0 < strlen($temp)) {
            for ($i = 0; $i < strlen($temp); $i++) {
              $char1 = $temp[$i];
              $char2 = ($i+1 < strlen($temp)) ? $temp[$i+1] : null;
              $char3 = ($i+2 < strlen($temp)) ? $temp[$i+2] : null;
              $char4 = ($i+3 < strlen($temp)) ? $temp[$i+3] : null;

              if ((0x20 <= ord($char1)) && (0x7E >= ord($char1))) {
                # add ASCII characters to string
                $string .= $char1;

                # print character to screen
                if (null !== $replace_char) {
                  print($replace_char);
                } else {
                  print($string[strlen($string)-1]);
                }
              } elseif ((0 === ((ord($char1) >> 0x05) ^ 0x06)) &&
                        (null !== $char2) &&
                        (0 === ((ord($char2) >> 0x06) ^ 0x02))) {
                # add 2-byte UTF-8 characters to string
                $string .= mb_convert_encoding($char1.$char2, "UTF-8");

                # print character to screen
                if (null !== $replace_char) {
                  print($replace_char);
                } else {
                  print($string[strlen($string)-1]);
                }

                # skip next 1 byte
                $i++;
              } elseif ((0 === ((ord($char1) >> 0x04) ^ 0x0E)) &&
                        (null !== $char2) &&
                        (0 === ((ord($char2) >> 0x06) ^ 0x02)) &&
                        (null !== $char3) &&
                        (0 === ((ord($char3) >> 0x06) ^ 0x02))) {
                # add 3-byte UTF-8 characters to string
                $string .= mb_convert_encoding($char1.$char2.$char3, "UTF-8");

                # print character to screen
                if (null !== $replace_char) {
                  print($replace_char);
                } else {
                  print($string[strlen($string)-1]);
                }

                # skip next 2 bytes
                $i++;
                $i++;
              } elseif ((0 === ((ord($char1) >> 0x03) ^ 0x1E)) &&
                        (null !== $char2) &&
                        (0 === ((ord($char2) >> 0x06) ^ 0x02)) &&
                        (null !== $char3) &&
                        (0 === ((ord($char3) >> 0x06) ^ 0x02)) &&
                        (null !== $char4) &&
                        (0 === ((ord($char4) >> 0x06) ^ 0x02))) {
                # add 4-byte UTF-8 characters to string
                $string .= mb_convert_encoding($char1.$char2.$char3.$char4, "UTF-8");

                # print character to screen
                if (null !== $replace_char) {
                  print($replace_char);
                } else {
                  print($string[strlen($string)-1]);
                }

                # skip next 3 bytes
                $i++;
                $i++;
                $i++;
              } elseif ((0x08 === ord($char1)) || (0x7F === ord($char1))) {
                # remove character from string
                if (0 < strlen($string)) {
                  # remove one character from string
                  $string = mb_substr($string, 0, -1);

                  # remove printed character from screen
                  print(chr(0x08).chr(0x20).chr(0x08));
                  #print(chr(0x1B).chr(0x5B).chr(0x44).chr(0x20).chr(0x1B).chr(0x5B).chr(0x44));
                }
              } elseif ((0x0A === ord($char1)) || (0x0D === ord($char1))) {
                # print line break to the screen
                print($char1);

                # exit the loop
                break;
              } elseif (0x1B === ord($char1)) {
                # move carriage back one step
                print(chr(0x07));

                # exit the loop
                break;
              } else {
                # ignore unknown characters
                # move carriage back one step
                print(chr(0x07));
              }
            }
          } else {
            # sleep a bit to not use up the whole CPU
            usleep(10000);
          }
        } while ((null === $char1) || ((0x0A !== ord($char1)) && (0x0D !== ord($char1))));

        if (0 < strlen($string)) {
          $result = $string;
        }
      } finally {
        readline_callback_handler_remove();
        stream_set_blocking(STDIN, true);
      }
    }

    return $result;
  }

  # PHP provides such a function but the standard library
  # of the Raspberry Pi Pico may not so we implement it
  # ourselves
  function deduplicatearray($array) {
    $result = null;

    if (is_array($array)) {
      $result = [];

      # we assume that the array is sorted and simply proceed
      # when the next character in the array differs from the
      # previously deduplicated character
      for ($i = 0; $i < count($array); $i++) {
        if ((0 >= count($result)) || ($array[$i] !== $result[count($result)-1])) {
          $result[] = $array[$i];
        }
      }
    }

    return $result;
  }

  # PHP provides such a function but the standard library
  # of the Raspberry Pi Pico may not so we implement it
  # ourselves
  function sortarray($array) {
    $result = null;

    if (is_array($array)) {
      $result = $array;

      # we just use a slightly optimized bubblesort
      for ($i = 0; $i < count($result); $i++) {
        for ($j = 1; $j < count($result)-$i; $j++) {
          if (ord($result[$j-1]) > ord($result[$j])) {
            $temp         = $result[$j-1];
            $result[$j-1] = $result[$j];
            $result[$j]   = $temp;
          }
        }
      }
    }

    return $result;
  }

  # parse the character set string and generate a
  # two-dimensional array so we know which characters
  # are valid in an encoded password
  function parsecharset($string) {
    $result = null;

    if (is_string($string)) {
      # get rid of junk
      $string = trim($string);

      # prepare the result
      $result = [[]];

      # prepare the range variables
      $first  = null;
      $range  = false;
      $second = null;

      for ($i = 0; $i < strlen($string); $i++) {
        switch (ord($string[$i])) {
          # separator characters start a new character group,
          # several separator characters in a row act as one
          # separator
          case 0x09:
          case 0x0A:
          case 0x0D:
          case 0x20: {
            # clean up the range variables so that their
            # content is accounted for in the current
            # character group
            if (null !== $first) {
              $result[count($result)-1][] = $first;
            }
            if ($range) {
              $result[count($result)-1][] = chr(0x2D);
            }

            # seperate two character groups but only if the
            # last character group contains at least one
            # character, otherwise we do nothing
            if (0 < count($result[count($result)-1])) {
              $result[] = [];
            }

            # reset the range variables
            $first  = null;
            $range  = false;
            $second = null;

            break;
          }

          # character ranges can be short coded with a minus sign
          # starting with the first character of the range and ending
          # with the last character of the range (e.g. 0-9 or A-Z or a-z)
          case 0x2D: {
            # we encountered a minus, if we have not encountered
            # a character before then we just handle it like any
            # other character, otherwise this might be a range
            if ((null !== $first) && (!$range)) {
              $range = true;

              break;
            } else {
              # this cannot be a range so we continue with the
              # the default handling characters by falling through
              # to the default case
            }
          }

          default: {
            # if we are not in a range then we just put the character
            # in the character group, otherwise we iterate through the
            # range and add all characters to the character group
            if (!$range) {
              # we have not encountered a range so we can add the
              # previous character to the character group
              if (null !== $first) {
                $result[count($result)-1][] = $first;
              }

              # store current character as $first in case a range is
              # coming up afterwards
              $first = $string[$i];
            } else {
              # we have encountered a range so prepare the iteration
              $second = $string[$i];

              # iterate over the range even if it is just a single character
              if (ord($first) <= ord($second)) {
                for ($char = ord($first); $char <= ord($second); $char++) {
                  $result[count($result)-1][] = chr($char);
                }
              } else {
                for ($char = ord($first); $char >= ord($second); $char--) {
                  $result[count($result)-1][] = chr($char);
                }
              }

              # reset the range variables
              $first  = null;
              $range  = false;
              $second = null;
            }
          }
        }
      }

      # clean up the range variables so that their
      # content is accounted for in the current
      # character group
      if (null !== $first) {
        $result[count($result)-1][] = $first;
      }
      if ($range) {
        $result[count($result)-1][] = chr(0x2D);
      }

      # clean up the character groups so that we
      # do not have an empty character group
      if (0 >= count($result[count($result)-1])) {
        unset($result[count($result)-1]);
      }

      # only proceed if there are character groups left
      if (0 >= count($result)) {
        $result = null;
      } else {
        # clean up the character groups to improve
        # reproducibility, characters within character
        # groups are sorted and deduplicated
        for ($i = 0; $i < count($result); $i++) {
          # sort the character group
          $result[$i] = sortarray($result[$i]);

          # deduplicate the character group
          $result[$i] = deduplicatearray($result[$i]);
        }

        # finally sort the character groups based on the first
        # characters within the character group so improve
        # reproducibility, just use a simple bubble sort for
        # that as well
        for ($a = 0; $a < count($result); $a++) {
          for ($b = 1; $b < count($result)-$a; $b++) {
            # make sure that we do not go out of bounds
            $max = count($result[$b-1]);
            if ($max > count($result[$b])) {
              $max = count($result[$b]);
            }

            # find the first character in the character groups that differs
            $pos = 0;
            while (($pos < $max) && ($result[$b-1][$pos] === $result[$b][$pos])) {
              $pos++;
            }

            if ($pos === $max) {
              # we did not find a character that differs, but maybe
              # one character group is larger than the other, the
              # smaller character group is sorted to the front
              if (count($result[$b-1]) > count($result[$b])) {
                $temp         = $result[$b-1];
                $result[$b-1] = $result[$b];
                $result[$b]   = $temp;
              }
            } else {
              # we found a character that differs
              if (ord($result[$b-1][$pos]) > ord($result[$b][$pos])) {
                $temp         = $result[$b-1];
                $result[$b-1] = $result[$b];
                $result[$b]   = $temp;
              }
            }
          }
        }
      }
    }

    return $result;
  }

  # in addition to the info there are other configuration values that need to be queried
  function queryconfig(&$length, &$charset, &$enforce, $mode = MODE_DEFAULT, $characterset = null) {
    $result = true;

    # set the defaults
    $charset = parsecharset(DEFAULT_CHARSET);
    $enforce = DEFAULT_ENFORCE;
    $length  = DEFAULT_LENGTH;

    switch ($mode) {
      case MODE_DEFAULT : {
        if ($result) {
          # handle password length
          $length = intval(readtext("Length", strval(DEFAULT_LENGTH)));
          if (0 >= $length) {
            println("");
            println("ERROR: length must be larger than 0");
            println("");

            $result = false;
          } elseif (1024 < $length) {
            println("");
            println("ERROR: length must be smaller than or equal to 1024");
            println("");

            $result = false;
          }
        }

        if ($result) {
          # handle password charset
          $charset = parsecharset(readtext("Characterset", DEFAULT_CHARSET));
          if (!is_array($charset)) {
            println("");
            println("ERROR: character set is malformed");
            println("");

            $result = false;
          }
        }

        if ($result) {
          # handle password enforce charset
          $enforce = filter_var(readtext("Enforce", ($enforce) ? "true" : "false"), FILTER_VALIDATE_BOOLEAN);

          # prevent us from entering an infinite loop as we
          # might not be able to enforce the character groups
          if ($enforce && (count($charset) > $length)) {
            println("");
            println("ERROR: length is smaller than the number of enforced character groups");
            println("");

            $result = false;
          }
        }

        break;
      }

      case MODE_DIEHARDER : {
        # we do nothing
        break;
      }

      case MODE_MODULOBIAS : {
        # only handle the given character set if it is not null
        if (null !== $characterset) {
          $charset = parsecharset($characterset);
          if (!is_array($charset)) {
            $result = false;
          }
        }

        break;
      }
    }

    return $result;
  }

  # generate the actual password based on the given secret
  # password and information string, during a dieharder run
  # we will just output the raw data
  function calcpw($pass, $info, $mode = MODE_DEFAULT, $characterset = null) {
    $result = null;

    if (is_string($pass) &&
        is_string($info) &&
        is_int($mode)) {
      if (queryconfig($length, $charset, $enforce, $mode, $characterset)) {
        # flatten the charset to be more time-constant during
        # the encoding, this way we do not have to switch between
        # arrays based on the random data, the generation of the
        # password is also more reproducible as we sort and
        # deduplicate everything
        $characters = [];
        for ($i = 0; $i < count($charset); $i++) {
          for ($j = 0; $j < count($charset[$i]); $j++) {
            $characters[] = $charset[$i][$j];
          }
        }
        $characters = sortarray($characters);
        $characters = deduplicatearray($characters);

        # get the max random number we can use to prevent modulo bias later on
        $max = floor(0x100 / count($characters)) * count($characters);

        # key derivation
        $pbkdf2 = hash_pbkdf2("sha256", $pass, $info, PBKDF2_ITERATIONS, 0, true);
        if (false !== $pbkdf2) {
          # random IV generation
          $counter = openssl_encrypt(hex2bin("00000000000000000000000000000000"), "aes-256-ecb",
                                     $pbkdf2, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, "");

          if (false !== $counter) {
            $result = "";

            # key expansion and and encoding
            do {
              # get one block of randomness
              $block = openssl_encrypt($counter, "aes-256-ecb",
                                       $pbkdf2, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, "");

              # handle block based on the execution mode
              switch ($mode) {
                case MODE_DEFAULT : {
                  # generate password characters
                  $i = 0;
                  while (($i < strlen($block)) && (strlen($result) < $length)) {
                    # get the character within the flattened charset
                    $char = $characters[ord($block[$i]) % count($characters)];

                    # only use bytes that are LOWER than the $max value so that
                    # we do not fall victim to the modulo bias
                    if (ord($block[$i]) < $max) {
                      $result .= $char;
                    }

                    # enforce the character groups if the length of
                    # the requested password is reached
                    if ($enforce && (strlen($result) >= $length)) {
                      $full = true;
                      for ($a = 0; $a < count($charset); $a++) {
                        $partial = false;

                        for ($b = 0; $b < count($charset[$a]); $b++) {
                          for ($c = 0; $c < strlen($result); $c++) {
                            # we do the comparison first to prevent lazy evaluation from
                            # hitting us and giving us a more time-constant execution
                            $partial = (($charset[$a][$b] === $result[$c]) || $partial);
                          }
                        }

                        # if a character from one character group is missing
                        # then we will switch to false and retry as a consequence,
                        # to be more time-constant we proceed with the check
                        $full = ($partial && $full);
                      }

                      # the check failed so we start again
                      if (!$full) {
                        $result = "";
                      }
                    }

                    # increment counter
                    $i++;
                  }

                  break;
                }

                case MODE_DIEHARDER : {
                  # in the dieharder mode we just output the raw blocks
                  print($block);

                  break;
                }

                case MODE_MODULOBIAS : {
                  # in the modulo bias mode we encode the bytes to characters
                  # based on the character set and output them
                  for ($i = 0; $i < strlen($block); $i++) {
                    # get the character within the flattened charset
                    $char = $characters[ord($block[$i]) % count($characters)];

                    # only use bytes that are LOWER than the $max value so that
                    # we do not fall victim to the modulo bias
                    if (ord($block[$i]) < $max) {
                      print($char);
                    }
                  }

                  break;
                }
              }

              # time-constant increment counter
              $increment = 0x01;
              for ($i = strlen($counter)-1; $i >= 0; $i--) {
                $temp        = ord($counter[$i]) + $increment;
                $counter[$i] = chr($temp % 0x100);
                $increment   = $temp >> 0x08;
              }
            } while ((strlen($result) < $length) || (MODE_DEFAULT !== $mode));
          }
        }
      }
    }

    return $result;
  }

  function main($arguments) {
    $result = 0;

    # check that the mbstring module is loaded
    if (!extension_loaded("mbstring")) {
      println("ERROR: mbstring extension is not loaded.");

      $result = 1;
    } elseif (!extension_loaded("openssl")) {
      println("ERROR: openssl extension is not loaded.");

      $result = 2;
    } elseif (1 < count($arguments)) {
      # call specific mode based on the first parameter
      switch ($arguments[1]) {
        case ARG_DIEHARDER : {
          if (4 !== count($arguments)) {
            println("ERROR: incorrect number of arguments");

            $result = 3;
          } else {
            if (null === calcpw($arguments[2], $arguments[3], MODE_DIEHARDER, null)) {
              println("ERROR: dieharder mode failed");

              $result = 4;
            }
          }

          break;
        }

        case ARG_MODULOBIAS : {
          if ((4 > count($arguments)) || (5 < count($arguments))) {
            println("ERROR: incorrect number of arguments");

            $result = 5;
          } else {
            $characterset = null;
            if (5 === count($arguments)) {
              $characterset = $arguments[4];
            }

            if (null === calcpw($arguments[2], $arguments[3], MODE_MODULOBIAS, $characterset)) {
              println("ERROR: modulo bias mode failed");

              $result = 6;
            }
          }

          break;
        }

        default : {
          println("ERROR: unknown command");

          $result = 7;
        }
      }
    } else {
      # handle normal execution
      do {
        $pass = readtext("Password", "", "*");

        if (!mb_check_encoding($pass, "ASCII")) {
          println("");
          println("ERROR: password contains illegal characters");
          println("");

          # retry
          $pass = null;
        } elseif (null === $pass) {
          println("");
          println("ERROR: password must not be empty");
          println("");
        } else {
          $repeat = readtext("Password", "", "*");

          if (!hash_equals($pass, $repeat)) {
            println("");
            println("ERROR: passwords do not match");
            println("");

            # retry
            $pass = null;
          }
        }
      } while (null === $pass);

      println("");

      do {
        $info = readtext("Information");

        if (!mb_check_encoding($info, "ASCII")) {
          println("");
          println("ERROR: information contains illegal characters");
          println("");
        } elseif (null === $info) {
          println("");
          println("ERROR: information must not be empty");
          println("");
        } else {
          $calculated = calcpw($pass, $info, MODE_DEFAULT, null);

          if (null !== $calculated) {
            println("");
            println($calculated);
            println("");
          }
        }
      } while (true);
    }

    return $result;
  }

  exit(main($argv));

